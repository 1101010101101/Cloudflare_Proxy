#!/usr/bin/env python3
"""
Create/check a GitHub repository, dispatch a GitHub Actions workflow,
install cloudflared if needed, and start an SSH SOCKS5 proxy tunnel.

Optional Python package:
  PyNaCl                 Enables GitHub Actions secret creation via REST API.

Authentication environment, choose one:
  GITHUB_TOKEN          Classic GitHub token with repo, workflow, admin:public_key.
  GH_TOKEN              Fallback token name, used when GITHUB_TOKEN is absent.
  GITHUB_OAUTH_CLIENT_ID OAuth App client ID for Device Flow fallback.
  GITHUB_OAUTH_CLIENT_SECRET optional OAuth App client secret for Device Flow.
                        Built-in CLIENT_ID/CLIENT_SECRET below are used if env vars are absent.

Optional environment:
  GITHUB_OAUTH_SCOPES  defaults to: repo workflow admin:public_key.
  GITHUB_OAUTH_OPEN_BROWSER true/false, defaults to true.
  GITHUB_TOKEN_CACHE_PATH optional path for saved OAuth token.
  GITHUB_REPO_PRIVATE  true/false, defaults to false.
  GITHUB_WORKFLOW_ID   workflow file name or numeric ID, defaults to deploy.yml.
  GITHUB_REF           branch/tag ref; defaults to the repository default branch.
  WORKFLOW_POLL        true/false, defaults to false.
  WORKFLOW_POLL_TIMEOUT seconds, defaults to 60 when polling is enabled.
  DISPATCH_WAIT_SECONDS seconds, defaults to 30 when polling is disabled.
  TUNNEL_URL_TIMEOUT   seconds to wait for trycloudflare hostname, defaults to 180.
  SSH_KEY_PATH         defaults to ~/.ssh/id_rsa.
  SSH_USER             defaults to proxyuser.
  SSH_HOST             optional hostname for a custom workflow (no unsafe default).
  SSH_HOST_KEY         required OpenSSH public host key when SSH_HOST is supplied.
  SOCKS_HOST           local bind IP, defaults to 127.0.0.1.
  SOCKS_PORT           defaults to 1081.
  CLOUDFLARED_LOCAL_PORT local TCP bridge port, defaults to 1082.
  CLOUDFLARED_ACCESS_MODE tcp/ssh, defaults to tcp.
  CLOUDFLARED_INSTALL_DIR optional installation directory.
  PROXY_WATCHDOG       true/false, defaults to true.
  WATCHDOG_INTERVAL_SECONDS seconds between background health checks, defaults to 60.
  PROXY_TEST_HOST      external host used for SOCKS5 health checks, defaults to www.cloudflare.com.
  PROXY_TEST_PORT      external port used for SOCKS5 health checks, defaults to 443.
"""

from __future__ import annotations

import base64
import ipaddress
import io
import json
import os
import platform
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
import webbrowser
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

try:
    import requests
except ImportError as exc:
    print("ERROR: Python package 'requests' is required. Install it with: pip install requests", file=sys.stderr)
    raise SystemExit(1) from exc


GITHUB_API = "https://api.github.com"
GITHUB_DEVICE_CODE_URL = "https://github.com/login/device/code"
GITHUB_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"
CLIENT_ID = "Ov23liCdaWDcDxNdsnwI"
CLIENT_SECRET = ""
REPO_NAME = "cloudflare-proxy"
DEFAULT_WORKFLOW_ID = "deploy.yml"
DEFAULT_SSH_USER = "proxyuser"
DEFAULT_SOCKS_HOST = "127.0.0.1"
DEFAULT_SOCKS_PORT = 1081
DEFAULT_CLOUDFLARED_LOCAL_PORT = 1082
DEFAULT_WORKFLOW_PATH = ".github/workflows/deploy.yml"
TUNNEL_INFO_ARTIFACT_NAME = "tunnel-info"
SSH_PUBLIC_KEY_SECRET_NAME = "PROXY_SSH_PUBLIC_KEY"
GITHUB_API_VERSION = "2026-03-10"
MANAGED_WORKFLOW_VERSION = 3
HTTP_TIMEOUT = 30
WORKFLOW_INDEX_TIMEOUT = 60
TUNNEL_URL_TIMEOUT = 180
TRYCLOUDFLARE_RE = re.compile(r"(?:https://)?([a-zA-Z0-9-]+\.trycloudflare\.com)")
SAFE_HOST_RE = re.compile(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}")
SSH_HOST_KEY_RE = re.compile(r"^(ssh-(?:ed25519|rsa))\s+([A-Za-z0-9+/=]+)(?:\s+.*)?$")
WATCHDOG_INTERVAL_SECONDS = 60
WATCHDOG_CHILD_ENV = "CLOUDFLARE_PROXY_WATCHDOG_CHILD"
JSON_EVENTS_ENV = "CLOUDFLARE_PROXY_JSON_EVENTS"
DEFAULT_PROXY_TEST_HOST = "www.cloudflare.com"
DEFAULT_PROXY_TEST_PORT = 443
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUPS = 3
TRANSIENT_HTTP_STATUSES = {429, 500, 502, 503, 504}
ACTIVE_WORKFLOW_STATUSES = {"queued", "in_progress", "waiting", "requested", "pending"}


class ScriptError(RuntimeError):
    """Expected user-facing failure."""


@dataclass(frozen=True)
class TunnelInfo:
    host: str
    ssh_host_key: str


def rotate_log(path: Path, max_bytes: int = LOG_MAX_BYTES, backups: int = LOG_BACKUPS) -> None:
    try:
        if not path.is_file() or path.stat().st_size < max_bytes:
            return
        oldest = path.with_name(f"{path.name}.{backups}")
        oldest.unlink(missing_ok=True)
        for number in range(backups - 1, 0, -1):
            source = path.with_name(f"{path.name}.{number}")
            if source.exists():
                source.replace(path.with_name(f"{path.name}.{number + 1}"))
        path.replace(path.with_name(f"{path.name}.1"))
    except OSError:
        pass


def log(message: str) -> None:
    if os.getenv(WATCHDOG_CHILD_ENV) == "1":
        path = watchdog_log_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            rotate_log(path)
            timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
            with path.open("a", encoding="utf-8") as handle:
                handle.write(f"{timestamp} {message}\n")
            return
        except OSError:
            pass
    print(message, file=sys.stderr)


def emit_event(
    stage: str,
    status: str,
    message: str,
    *,
    progress: int | None = None,
    endpoint: str | None = None,
    auth_code: str | None = None,
    auth_url: str | None = None,
) -> None:
    if os.getenv(JSON_EVENTS_ENV) != "1":
        return
    payload: dict[str, Any] = {
        "type": "proxy_event",
        "stage": stage,
        "status": status,
        "message": message,
    }
    if progress is not None:
        payload["progress"] = max(0, min(progress, 100))
    if endpoint:
        payload["endpoint"] = endpoint
    if auth_code:
        payload["auth_code"] = auth_code
    if auth_url:
        payload["auth_url"] = auth_url
    print(json.dumps(payload, ensure_ascii=False), flush=True)


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    raise ScriptError(f"Invalid boolean value: {value!r}")


def parse_int_env(name: str, default: int, min_value: int = 0) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ScriptError(f"{name} must be an integer, got {raw!r}") from exc
    if value < min_value:
        raise ScriptError(f"{name} must be >= {min_value}, got {value}")
    return value


def parse_port_env(name: str, default: int) -> int:
    value = parse_int_env(name, default, min_value=1)
    if value > 65535:
        raise ScriptError(f"{name} must be <= 65535, got {value}")
    return value


def parse_socks_host_env() -> str:
    raw = os.getenv("SOCKS_HOST", DEFAULT_SOCKS_HOST).strip()
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ScriptError(f"SOCKS_HOST must be an IP address, got {raw!r}") from exc
    if address.is_multicast:
        raise ScriptError(f"SOCKS_HOST must not be a multicast address, got {raw!r}")
    return str(address)


def socks_probe_host(bind_host: str) -> str:
    if bind_host == "0.0.0.0":
        return "127.0.0.1"
    if bind_host == "::":
        return "::1"
    return bind_host


def format_host_port(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def parse_positive_int(value: Any, field_name: str, default: int) -> int:
    if value is None:
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ScriptError(f"GitHub OAuth field {field_name!r} must be an integer, got {value!r}") from exc
    if parsed <= 0:
        raise ScriptError(f"GitHub OAuth field {field_name!r} must be positive, got {parsed}")
    return parsed


def windows_hidden_creationflags() -> int:
    if os.name != "nt":
        return 0
    return subprocess.CREATE_NO_WINDOW


def windows_hidden_startupinfo() -> Any:
    if os.name != "nt":
        return None
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    return startupinfo


def windows_detached_hidden_creationflags() -> int:
    if os.name != "nt":
        return 0
    return subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW


def first_env(*names: str) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return None


def expand_path(raw: str) -> Path:
    return Path(os.path.expandvars(raw)).expanduser().resolve()


def runtime_dir() -> Path:
    if os.name == "nt":
        base = os.getenv("APPDATA") or str(Path.home())
        return Path(base) / "cloudflare_proxy"
    return Path.home() / ".config" / "cloudflare_proxy"


def github_token_cache_path() -> Path:
    configured = os.getenv("GITHUB_TOKEN_CACHE_PATH")
    if configured:
        return expand_path(configured)
    suffix = "github_token.txt" if os.name == "nt" else "github_token"
    return runtime_dir() / suffix


def watchdog_pid_path() -> Path:
    return runtime_dir() / "watchdog.pid"


def watchdog_log_path() -> Path:
    return runtime_dir() / "watchdog.log"


def watchdog_claim_path() -> Path:
    return runtime_dir() / "watchdog.starting"


def proxy_state_path() -> Path:
    return runtime_dir() / "proxy-processes.json"


def recovery_state_path() -> Path:
    return runtime_dir() / "recovery-state.json"


def crash_log_path() -> Path:
    return runtime_dir() / "crash.log"


def write_crash_report() -> Path:
    path = crash_log_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        rotate_log(path)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"\n--- {datetime.now().astimezone().isoformat(timespec='seconds')} ---\n")
            traceback.print_exc(file=handle)
    except OSError:
        pass
    return path


def atomic_write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(value, encoding="utf-8")
        temporary.replace(path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def read_json_file(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def write_json_file(path: Path, payload: dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(payload, ensure_ascii=True, sort_keys=True))


def process_command_line(pid: int) -> str | None:
    if pid <= 0:
        return None
    if os.name == "nt":
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    (
                        f"$c=(Get-CimInstance Win32_Process -Filter \"ProcessId = {pid}\").CommandLine; "
                        "if ($null -ne $c) { "
                        "[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($c)) }"
                    ),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="ascii",
                errors="strict",
                timeout=10,
                check=False,
                creationflags=windows_hidden_creationflags(),
                startupinfo=windows_hidden_startupinfo(),
            )
        except (OSError, subprocess.SubprocessError, UnicodeError):
            return None
        encoded = (result.stdout or "").strip()
        if not encoded:
            return None
        try:
            return base64.b64decode(encoded, validate=True).decode("utf-16-le")
        except (ValueError, UnicodeError):
            return None

    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", errors="replace")
    except OSError:
        return None


def process_matches(pid: int, fragments: list[str]) -> bool:
    command_line = process_command_line(pid)
    if not command_line:
        return False
    normalized = command_line.casefold()
    return all(fragment.casefold() in normalized for fragment in fragments)


def terminate_owned_process(pid: int, fragments: list[str]) -> bool:
    if not is_process_running(pid) or not process_matches(pid, fragments):
        return False
    try:
        if os.name == "nt":
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", f"Stop-Process -Id {pid} -Force"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
                creationflags=windows_hidden_creationflags(),
                startupinfo=windows_hidden_startupinfo(),
            )
        else:
            os.kill(pid, 15)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def stop_owned_proxy_processes() -> None:
    state = read_json_file(proxy_state_path())
    raw_socks_host = state.get("socks_host", DEFAULT_SOCKS_HOST)
    socks_host = raw_socks_host if isinstance(raw_socks_host, str) else DEFAULT_SOCKS_HOST
    try:
        socks_port = int(state.get("socks_port", DEFAULT_SOCKS_PORT))
    except (TypeError, ValueError):
        socks_port = DEFAULT_SOCKS_PORT
    try:
        local_port = int(state.get("local_port", DEFAULT_CLOUDFLARED_LOCAL_PORT))
    except (TypeError, ValueError):
        local_port = DEFAULT_CLOUDFLARED_LOCAL_PORT
    ssh_pid = state.get("ssh_pid")
    cloudflared_pid = state.get("cloudflared_pid")
    if isinstance(ssh_pid, int):
        terminate_owned_process(ssh_pid, ["ssh", "-d", format_host_port(socks_host, socks_port)])
    if isinstance(cloudflared_pid, int):
        terminate_owned_process(cloudflared_pid, ["cloudflared", "access", "--url", f"{DEFAULT_SOCKS_HOST}:{local_port}"])
    try:
        proxy_state_path().unlink(missing_ok=True)
    except OSError:
        pass


def read_cached_github_token() -> str | None:
    path = github_token_cache_path()
    if not path.is_file():
        return None

    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        log(f"Could not read cached GitHub token from {path}: {exc}")
        return None

    if token:
        log(f"Using cached GitHub OAuth token from {path}.")
        return token
    return None


def save_cached_github_token(token: str) -> None:
    path = github_token_cache_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(token + "\n", encoding="utf-8")
        if os.name != "nt":
            path.chmod(0o600)
    except OSError as exc:
        log(f"Could not save GitHub OAuth token to {path}: {exc}")
        return

    log(f"Saved GitHub OAuth token to {path}.")


def delete_cached_github_token() -> None:
    path = github_token_cache_path()
    try:
        if path.exists():
            path.unlink()
    except OSError as exc:
        log(f"Could not delete cached GitHub token at {path}: {exc}")


def is_process_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
            if not handle:
                return False
            try:
                exit_code = wintypes.DWORD()
                if not ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    return False
                return exit_code.value == 259
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            return False

    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def read_watchdog_pid() -> int | None:
    path = watchdog_pid_path()
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def write_watchdog_pid(pid: int) -> None:
    atomic_write_text(watchdog_pid_path(), str(pid))


def watchdog_is_running() -> bool:
    pid = read_watchdog_pid()
    if not pid or pid == os.getpid() or not is_process_running(pid):
        return False
    return process_matches(pid, [Path(__file__).name, "--watchdog"])


def stop_duplicate_watchdogs(exclude_pid: int | None = None) -> None:
    if os.name != "nt":
        return
    exclusion = f" -and $_.ProcessId -ne {exclude_pid}" if exclude_pid else ""
    try:
        subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-CimInstance Win32_Process | "
                    "Where-Object { $_.Name -eq 'pythonw.exe' "
                    "-and $_.CommandLine -like '*cloudflare_proxy_setup.py*--watchdog*'"
                    f"{exclusion} }} | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force }}"
                ),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
            creationflags=windows_hidden_creationflags(),
            startupinfo=windows_hidden_startupinfo(),
        )
    except (OSError, subprocess.SubprocessError):
        pass


def claim_watchdog_start() -> bool:
    path = watchdog_claim_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    for _ in range(2):
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                age = time.time() - path.stat().st_mtime
            except OSError:
                age = 0
            if age < 30:
                return False
            try:
                path.unlink()
            except OSError:
                return False
            continue
        try:
            os.write(descriptor, f"{os.getpid()}\n".encode("ascii"))
        finally:
            os.close(descriptor)
        return True
    return False


def python_for_watchdog() -> str:
    if os.name == "nt":
        pythonw = Path(sys.executable).with_name("pythonw.exe")
        if pythonw.is_file():
            return str(pythonw)
    return sys.executable


def start_watchdog_if_needed(restart: bool = False) -> None:
    if os.getenv(WATCHDOG_CHILD_ENV) == "1":
        return
    if not parse_bool(os.getenv("PROXY_WATCHDOG"), default=True):
        return
    if watchdog_is_running():
        if not restart:
            log(f"Proxy watchdog is already running with PID {read_watchdog_pid()}.")
            return
        log(f"Restarting proxy watchdog with updated code (old PID {read_watchdog_pid()}).")
        stop_watchdog_process()
    if restart:
        stop_duplicate_watchdogs(exclude_pid=os.getpid())
    if not claim_watchdog_start():
        log("Proxy watchdog is already running or being started by another instance.")
        return

    log_path = watchdog_log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    command = [python_for_watchdog(), str(Path(__file__).resolve()), "--watchdog"]
    env = os.environ.copy()
    env[WATCHDOG_CHILD_ENV] = "1"

    popen_kwargs: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "env": env,
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = windows_detached_hidden_creationflags()
        popen_kwargs["startupinfo"] = windows_hidden_startupinfo()
        popen_kwargs["close_fds"] = True
    else:
        popen_kwargs["start_new_session"] = True

    try:
        process = subprocess.Popen(command, **popen_kwargs)
    except OSError as exc:
        raise ScriptError(f"Failed to start background proxy watchdog: {exc}") from exc
    finally:
        try:
            watchdog_claim_path().unlink(missing_ok=True)
        except OSError:
            pass

    write_watchdog_pid(process.pid)
    log(f"Started background proxy watchdog with PID {process.pid}. Log: {log_path}")


def stop_watchdog_process() -> None:
    pid = read_watchdog_pid()
    if not pid or not is_process_running(pid):
        return

    if not process_matches(pid, [Path(__file__).name, "--watchdog"]):
        log(f"Ignoring stale watchdog PID {pid}: it belongs to another process.")
        try:
            watchdog_pid_path().unlink(missing_ok=True)
        except OSError:
            pass
        return

    if os.name == "nt":
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", f"Stop-Process -Id {pid} -Force"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=10,
                check=False,
                creationflags=windows_hidden_creationflags(),
                startupinfo=windows_hidden_startupinfo(),
            )
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        try:
            os.kill(pid, 15)
        except OSError:
            pass

    try:
        watchdog_pid_path().unlink(missing_ok=True)
    except OSError:
        pass


def post_github_oauth(url: str, payload: dict[str, str]) -> dict[str, Any]:
    try:
        response = requests.post(
            url,
            data=payload,
            headers={
                "Accept": "application/json",
                "User-Agent": "cloudflare-proxy-bootstrap/1.0",
            },
            timeout=HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise ScriptError(f"Network error during GitHub OAuth authorization: {exc}") from exc

    if response.status_code != 200:
        raise ScriptError(f"GitHub OAuth request failed with HTTP {response.status_code}: {response.text.strip()}")

    try:
        data = response.json()
    except ValueError as exc:
        raise ScriptError("GitHub OAuth response was not valid JSON.") from exc

    if not isinstance(data, dict):
        raise ScriptError("GitHub OAuth response had an unexpected format.")
    return data


def get_token_from_device_flow() -> str:
    client_id = first_env("GITHUB_OAUTH_CLIENT_ID", "GITHUB_DEVICE_CLIENT_ID", "CLIENT_ID") or CLIENT_ID
    if not client_id:
        raise ScriptError(
            "GITHUB_TOKEN is not set. To use interactive browser authorization like the example, "
            "set GITHUB_OAUTH_CLIENT_ID to a GitHub OAuth App client ID."
        )

    scopes = os.getenv("GITHUB_OAUTH_SCOPES", "repo workflow admin:public_key")
    device_payload = {
        "client_id": client_id,
        "scope": scopes,
    }
    device_data = post_github_oauth(GITHUB_DEVICE_CODE_URL, device_payload)

    user_code = device_data.get("user_code")
    device_code = device_data.get("device_code")
    verification_uri = device_data.get("verification_uri")
    interval = parse_positive_int(device_data.get("interval"), "interval", 5)
    expires_in = parse_positive_int(device_data.get("expires_in"), "expires_in", 900)
    if not all(isinstance(value, str) and value for value in (user_code, device_code, verification_uri)):
        raise ScriptError(f"GitHub OAuth device response is incomplete: {device_data}")

    log("GITHUB_TOKEN is not set. Starting GitHub OAuth Device Flow.")
    log(f"Open this URL: {verification_uri}")
    log(f"Enter this code: {user_code}")
    emit_event(
        "github_auth",
        "action_required",
        "Введите код на открывшейся странице GitHub",
        progress=20,
        auth_code=user_code,
        auth_url=verification_uri,
    )
    if parse_bool(os.getenv("GITHUB_OAUTH_OPEN_BROWSER"), default=True):
        try:
            webbrowser.open(verification_uri)
        except webbrowser.Error:
            pass

    token_payload = {
        "client_id": client_id,
        "device_code": device_code,
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
    }
    client_secret = first_env("GITHUB_OAUTH_CLIENT_SECRET", "GITHUB_DEVICE_CLIENT_SECRET", "CLIENT_SECRET") or CLIENT_SECRET
    if client_secret:
        token_payload["client_secret"] = client_secret

    deadline = time.monotonic() + expires_in
    while time.monotonic() < deadline:
        time.sleep(interval)
        token_data = post_github_oauth(GITHUB_ACCESS_TOKEN_URL, token_payload)
        access_token = token_data.get("access_token")
        if isinstance(access_token, str) and access_token:
            log("GitHub OAuth authorization succeeded.")
            return access_token

        error = token_data.get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval += 5
            continue
        if error == "access_denied":
            raise ScriptError("GitHub OAuth authorization was denied.")
        if error == "expired_token":
            raise ScriptError("GitHub OAuth device code expired before authorization completed.")
        raise ScriptError(f"GitHub OAuth authorization failed: {token_data}")

    raise ScriptError("GitHub OAuth device authorization timed out.")


def get_github_token(allow_device_flow: bool = True) -> str:
    token = first_env("GITHUB_TOKEN", "GH_TOKEN")
    if token:
        log("Using GitHub token from environment.")
        return token

    cached_token = read_cached_github_token()
    if cached_token:
        try:
            get_authenticated_user(cached_token)
            return cached_token
        except ScriptError as exc:
            if "HTTP 401" in str(exc):
                log("Cached GitHub OAuth token is invalid or expired. Removing it.")
                delete_cached_github_token()
            else:
                raise

    if not allow_device_flow:
        raise ScriptError("No valid cached GitHub token is available for background watchdog.")

    token = get_token_from_device_flow()
    save_cached_github_token(token)
    return token


def github_headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "cloudflare-proxy-bootstrap/1.0",
        "X-GitHub-Api-Version": os.getenv("GITHUB_API_VERSION", GITHUB_API_VERSION),
    }


def github_error(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text.strip() or response.reason

    message = payload.get("message") if isinstance(payload, dict) else None
    errors = payload.get("errors") if isinstance(payload, dict) else None
    if errors:
        return f"{message}; details: {json.dumps(errors, ensure_ascii=True)}"
    return message or response.reason


def github_request(
    method: str,
    path: str,
    token: str,
    *,
    expected: set[int],
    json_body: dict[str, Any] | None = None,
    retryable: bool | None = None,
) -> requests.Response:
    url = f"{GITHUB_API}{path}"
    method = method.upper()
    if retryable is None:
        retryable = method in {"GET", "HEAD", "PUT", "PATCH", "DELETE"}
    attempts = parse_int_env("GITHUB_API_RETRIES", 4, min_value=1) if retryable else 1

    response: requests.Response | None = None
    for attempt in range(1, attempts + 1):
        try:
            response = requests.request(
                method,
                url,
                headers=github_headers(token),
                json=json_body,
                timeout=HTTP_TIMEOUT,
            )
        except requests.RequestException as exc:
            if attempt >= attempts:
                raise ScriptError(f"Network error while calling GitHub API {method} {path}: {exc}") from exc
            delay = min(2 ** (attempt - 1), 15)
            log(f"Transient GitHub network error; retrying in {delay}s ({attempt}/{attempts}): {exc}")
            time.sleep(delay)
            continue

        if response.status_code in TRANSIENT_HTTP_STATUSES and attempt < attempts:
            retry_after = response.headers.get("Retry-After", "").strip()
            try:
                delay = max(1, min(int(retry_after), 60)) if retry_after else min(2 ** (attempt - 1), 15)
            except ValueError:
                delay = min(2 ** (attempt - 1), 15)
            log(f"GitHub API returned HTTP {response.status_code}; retrying in {delay}s ({attempt}/{attempts}).")
            time.sleep(delay)
            continue
        break

    if response is None:
        raise ScriptError(f"GitHub API {method} {path} did not return a response.")

    if response.status_code not in expected:
        detail = github_error(response)
        if response.status_code == 401:
            detail = f"{detail}. Check that GITHUB_TOKEN is valid."
        elif response.status_code == 403:
            detail = f"{detail}. Check token scopes and rate limits."
        raise ScriptError(f"GitHub API {method} {path} failed with HTTP {response.status_code}: {detail}")

    return response


def get_authenticated_user(token: str) -> str:
    response = github_request("GET", "/user", token, expected={200})
    login = response.json().get("login")
    if not login:
        raise ScriptError("GitHub API /user response does not contain a login.")
    return str(login)


def ensure_repository(token: str, owner: str, repo_name: str) -> dict[str, Any]:
    path = f"/repos/{quote(owner, safe='')}/{quote(repo_name, safe='')}"
    private = parse_bool(os.getenv("GITHUB_REPO_PRIVATE"), default=False)
    response = github_request("GET", path, token, expected={200, 404})
    if response.status_code == 200:
        log(f"Repository {owner}/{repo_name} already exists.")
        repo = response.json()
        if bool(repo.get("private")) != private:
            if not parse_bool(os.getenv("GITHUB_REPO_ALLOW_VISIBILITY_CHANGE"), default=False):
                current = "private" if repo.get("private") else "public"
                requested = "private" if private else "public"
                raise ScriptError(
                    f"Repository {owner}/{repo_name} is {current}, but {requested} was requested. "
                    "The script will not change existing repository visibility automatically. "
                    "Change it manually or explicitly set GITHUB_REPO_ALLOW_VISIBILITY_CHANGE=true."
                )
            log(f"Explicitly authorized: updating repository visibility to {'private' if private else 'public'}.")
            response = github_request(
                "PATCH",
                path,
                token,
                expected={200},
                json_body={"private": private},
            )
            return response.json()
        return repo

    log(f"Repository {owner}/{repo_name} does not exist. Creating it as {'private' if private else 'public'}.")
    response = github_request(
        "POST",
        "/user/repos",
        token,
        expected={201},
        json_body={
            "name": repo_name,
            "private": private,
            "auto_init": True,
        },
    )
    return response.json()


def workflow_path_from_id(workflow_id: str) -> str | None:
    if workflow_id.isdigit():
        return None
    if "/" in workflow_id:
        return workflow_id.lstrip("/")
    if workflow_id.endswith((".yml", ".yaml")):
        return f".github/workflows/{workflow_id}"
    return DEFAULT_WORKFLOW_PATH


def default_workflow_content() -> str:
    return f"# cloudflare-proxy-managed-version: {MANAGED_WORKFLOW_VERSION}\n" + """name: Cloudflare Tunnel Proxy

on:
  workflow_dispatch:
    inputs:
      ssh_public_key:
        description: Public SSH key allowed for proxyuser
        required: false
        type: string

permissions:
  contents: read

jobs:
  proxy:
    runs-on: ubuntu-latest
    timeout-minutes: 360
    steps:
      - name: Install cloudflared
        shell: bash
        run: |
          set -euo pipefail
          curl -fsSL -o /tmp/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
          sudo install -m 0755 /tmp/cloudflared /usr/local/bin/cloudflared
          cloudflared --version

      - name: Configure SSH server
        shell: bash
        env:
          SSH_PUBLIC_KEY_SECRET: ${{ secrets.PROXY_SSH_PUBLIC_KEY }}
          SSH_PUBLIC_KEY_INPUT: ${{ inputs.ssh_public_key }}
        run: |
          set -euo pipefail
          sudo apt-get update
          sudo apt-get install -y openssh-server
          sudo mkdir -p /run/sshd
          if ! id proxyuser >/dev/null 2>&1; then
            sudo useradd -m -s /bin/bash proxyuser
          fi
          sudo mkdir -p /home/proxyuser/.ssh
          SSH_PUBLIC_KEY="$SSH_PUBLIC_KEY_SECRET"
          if [ -z "$SSH_PUBLIC_KEY" ]; then
            SSH_PUBLIC_KEY="$SSH_PUBLIC_KEY_INPUT"
          fi
          if [ -z "$SSH_PUBLIC_KEY" ]; then
            echo "SSH public key is required"
            exit 1
          fi
          if ! printf '%s\\n' "$SSH_PUBLIC_KEY" | grep -Eq '^ssh-(ed25519|rsa) [A-Za-z0-9+/=]+([[:space:]].*)?$'; then
            echo "SSH public key has an invalid format"
            exit 1
          fi
          printf '%s\\n' "$SSH_PUBLIC_KEY" | sudo tee /home/proxyuser/.ssh/authorized_keys >/dev/null
          sudo chown -R proxyuser:proxyuser /home/proxyuser/.ssh
          sudo chmod 700 /home/proxyuser/.ssh
          sudo chmod 600 /home/proxyuser/.ssh/authorized_keys
          sudo passwd -l proxyuser || true
          sudo tee /etc/ssh/sshd_config.d/99-cloudflare-proxy.conf >/dev/null <<'EOF'
          PasswordAuthentication no
          KbdInteractiveAuthentication no
          PubkeyAuthentication yes
          AllowTcpForwarding yes
          GatewayPorts no
          X11Forwarding no
          AllowAgentForwarding no
          EOF
          sudo /usr/sbin/sshd -t
          sudo /usr/sbin/sshd
          sudo cat /etc/ssh/ssh_host_ed25519_key.pub > ssh_host_key.pub

      - name: Start Cloudflare quick tunnel
        shell: bash
        run: |
          set -euo pipefail
          nohup cloudflared tunnel --url ssh://localhost:22 --no-autoupdate > cloudflared.log 2>&1 &
          echo $! > cloudflared.pid
          mkdir -p tunnel-info
          TUNNEL_URL=""
          for i in {1..60}; do
            TUNNEL_URL="$(grep -Eo 'https://[a-zA-Z0-9-]+\\.trycloudflare\\.com' cloudflared.log | tail -n 1 || true)"
            if [ -n "$TUNNEL_URL" ]; then
              break
            fi
            sleep 2
          done
          if [ -z "$TUNNEL_URL" ]; then
            cat cloudflared.log
            exit 1
          fi
          TUNNEL_HOST="${TUNNEL_URL#https://}"
          printf '%s\\n' "$TUNNEL_HOST" > tunnel-info/host.txt
          printf '%s\\n' "$TUNNEL_URL" > tunnel-info/url.txt
          cp ssh_host_key.pub tunnel-info/ssh_host_key.pub
          printf 'Cloudflare tunnel: %s\\n' "$TUNNEL_URL"
          cat cloudflared.log

      - name: Upload tunnel info
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: tunnel-info
          path: tunnel-info/

      - name: Keep proxy alive
        shell: bash
        run: |
          set -euo pipefail
          while pgrep -f 'cloudflared tunnel --url ssh://localhost:22' >/dev/null && timeout 2 bash -c '</dev/tcp/127.0.0.1/22' 2>/dev/null; do
            sleep 10
          done
          echo "cloudflared or sshd exited unexpectedly"
          tail -n 200 cloudflared.log || true
          exit 1
"""


def branch_exists(token: str, owner: str, repo: str, ref: str) -> bool:
    path = f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/branches/{quote(ref, safe='')}"
    response = github_request("GET", path, token, expected={200, 404})
    return response.status_code == 200


def get_repository_file(token: str, owner: str, repo: str, file_path: str, ref: str) -> requests.Response:
    encoded_owner = quote(owner, safe="")
    encoded_repo = quote(repo, safe="")
    encoded_path = quote(file_path, safe="/")
    encoded_ref = quote(ref, safe="")
    return github_request(
        "GET",
        f"/repos/{encoded_owner}/{encoded_repo}/contents/{encoded_path}?ref={encoded_ref}",
        token,
        expected={200, 404},
    )


def decode_content_response(response: requests.Response) -> str:
    payload = response.json()
    encoded = payload.get("content", "")
    if not isinstance(encoded, str):
        return ""
    try:
        return base64.b64decode(encoded.replace("\n", "")).decode("utf-8", errors="replace")
    except (ValueError, TypeError):
        return ""


def put_repository_file(
    token: str,
    owner: str,
    repo: str,
    file_path: str,
    ref: str | None,
    content: str,
    *,
    sha: str | None = None,
) -> None:
    encoded_owner = quote(owner, safe="")
    encoded_repo = quote(repo, safe="")
    encoded_path = quote(file_path, safe="/")
    payload = {
        "message": "Add deploy workflow",
        "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
    }
    if ref:
        payload["branch"] = ref
    if sha:
        payload["message"] = "Update deploy workflow"
        payload["sha"] = sha

    github_request(
        "PUT",
        f"/repos/{encoded_owner}/{encoded_repo}/contents/{encoded_path}",
        token,
        expected={200, 201},
        json_body=payload,
    )


def wait_for_workflow_available(token: str, owner: str, repo: str, workflow_id: str) -> None:
    encoded_owner = quote(owner, safe="")
    encoded_repo = quote(repo, safe="")
    encoded_workflow = quote(workflow_id, safe="")
    path = f"/repos/{encoded_owner}/{encoded_repo}/actions/workflows/{encoded_workflow}"
    deadline = time.monotonic() + WORKFLOW_INDEX_TIMEOUT

    while time.monotonic() < deadline:
        response = github_request("GET", path, token, expected={200, 404})
        if response.status_code == 200:
            return
        time.sleep(3)

    raise ScriptError(f"Workflow {workflow_id!r} was created, but GitHub Actions did not index it in time.")


def ensure_workflow_file(token: str, owner: str, repo: str, workflow_id: str, ref: str) -> tuple[bool, bool]:
    file_path = workflow_path_from_id(workflow_id)
    if not file_path:
        log(f"Workflow ID {workflow_id!r} is numeric, so the script cannot auto-create a missing workflow file.")
        wait_for_workflow_available(token, owner, repo, workflow_id)
        return False, False

    if branch_exists(token, owner, repo, ref):
        response = get_repository_file(token, owner, repo, file_path, ref)
        if response.status_code == 200:
            log(f"Workflow file {file_path} already exists.")
            payload = response.json()
            sha = payload.get("sha") if isinstance(payload, dict) else None
            content = decode_content_response(response)
            is_managed = "Cloudflare Tunnel Proxy" in content or "cloudflare-proxy-managed-version:" in content
            if not is_managed:
                raise ScriptError(
                    f"Workflow file {file_path} already exists but is not managed by this script. "
                    "Choose another GITHUB_WORKFLOW_ID or remove the conflicting file manually."
                )
            should_update = content != default_workflow_content()
            if should_update:
                if not isinstance(sha, str) or not sha:
                    raise ScriptError(f"Could not update {file_path}: GitHub did not return a file sha.")
                log(f"Updating managed workflow file {file_path}.")
                put_repository_file(token, owner, repo, file_path, ref, default_workflow_content(), sha=sha)
                wait_for_workflow_available(token, owner, repo, workflow_id)
                return True, True
            return False, "ssh_public_key" in content or "PROXY_SSH_PUBLIC_KEY" in content

        log(f"Workflow file {file_path} is missing. Creating it on branch {ref}.")
        put_repository_file(token, owner, repo, file_path, ref, default_workflow_content())
    else:
        raise ScriptError(
            f"Branch {ref!r} does not exist in {owner}/{repo}. "
            "Set GITHUB_REF to an existing branch or create it first."
        )

    wait_for_workflow_available(token, owner, repo, workflow_id)
    return True, True


def dispatch_workflow(
    token: str,
    owner: str,
    repo: str,
    workflow_id: str,
    ref: str,
    inputs: dict[str, str] | None = None,
) -> tuple[datetime, dict[str, Any] | None]:
    encoded_owner = quote(owner, safe="")
    encoded_repo = quote(repo, safe="")
    encoded_workflow = quote(workflow_id, safe="")
    path = f"/repos/{encoded_owner}/{encoded_repo}/actions/workflows/{encoded_workflow}/dispatches"
    dispatched_at = datetime.now(timezone.utc)

    log(f"Dispatching workflow {workflow_id!r} on ref {ref!r}.")
    try:
        response = github_request(
            "POST",
            path,
            token,
            expected={200, 204},
            json_body={"ref": ref, **({"inputs": inputs} if inputs else {})},
            retryable=False,
        )
    except ScriptError as exc:
        # A POST can succeed server-side even if its response is lost. Reconcile
        # once instead of blindly dispatching a duplicate runner.
        log(f"Workflow dispatch response was uncertain; checking recent runs before failing: {exc}")
        time.sleep(5)
        run = find_run_started_after(get_recent_workflow_runs(token, owner, repo, workflow_id, ref), dispatched_at)
        if run:
            return dispatched_at, run
        raise

    if response.status_code == 200:
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        run_id = payload.get("workflow_run_id") if isinstance(payload, dict) else None
        if isinstance(run_id, int):
            return dispatched_at, {
                "id": run_id,
                "html_url": payload.get("html_url", "URL unavailable"),
                "status": "requested",
            }
    return dispatched_at, None


def get_recent_workflow_runs(token: str, owner: str, repo: str, workflow_id: str, ref: str) -> list[dict[str, Any]]:
    encoded_owner = quote(owner, safe="")
    encoded_repo = quote(repo, safe="")
    encoded_workflow = quote(workflow_id, safe="")
    encoded_ref = quote(ref, safe="")
    path = (
        f"/repos/{encoded_owner}/{encoded_repo}/actions/workflows/{encoded_workflow}/runs"
        f"?branch={encoded_ref}&event=workflow_dispatch&per_page=5"
    )
    response = github_request("GET", path, token, expected={200})
    runs = response.json().get("workflow_runs", [])
    if not isinstance(runs, list):
        return []
    return runs


def get_active_workflow_run(token: str, owner: str, repo: str, workflow_id: str, ref: str) -> dict[str, Any] | None:
    runs = get_recent_workflow_runs(token, owner, repo, workflow_id, ref)

    for run in runs:
        status = run.get("status")
        if isinstance(status, str) and status in ACTIVE_WORKFLOW_STATUSES:
            log(f"Found already running workflow: {run.get('html_url', 'URL unavailable')}")
            return run
    return None


def cancel_workflow_run(token: str, owner: str, repo: str, run_id: int) -> None:
    encoded_owner = quote(owner, safe="")
    encoded_repo = quote(repo, safe="")
    response = github_request(
        "POST",
        f"/repos/{encoded_owner}/{encoded_repo}/actions/runs/{run_id}/cancel",
        token,
        expected={202, 409},
        retryable=False,
    )
    if response.status_code == 202:
        log(f"Requested cancellation of unhealthy workflow run {run_id}.")


def wait_for_run_inactive(token: str, owner: str, repo: str, run_id: int, timeout: int = 30) -> None:
    encoded_owner = quote(owner, safe="")
    encoded_repo = quote(repo, safe="")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = github_request(
            "GET",
            f"/repos/{encoded_owner}/{encoded_repo}/actions/runs/{run_id}",
            token,
            expected={200, 404},
        )
        if response.status_code == 404:
            return
        try:
            status = response.json().get("status")
        except (ValueError, AttributeError):
            status = None
        if status not in ACTIVE_WORKFLOW_STATUSES:
            return
        time.sleep(3)
    log(f"Workflow run {run_id} is still active after cancellation timeout; continuing cautiously.")


def parse_github_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def find_run_started_after(runs: list[dict[str, Any]], dispatched_at: datetime) -> dict[str, Any] | None:
    # GitHub timestamps can lag the dispatch response by a few seconds.
    threshold = dispatched_at.timestamp() - 10
    for run in runs:
        created_at = parse_github_timestamp(run.get("created_at"))
        if created_at and created_at.timestamp() >= threshold:
            return run
    return None


def wait_for_workflow_start(
    token: str,
    owner: str,
    repo: str,
    workflow_id: str,
    ref: str,
    dispatched_at: datetime,
) -> dict[str, Any] | None:
    if parse_bool(os.getenv("WORKFLOW_POLL"), default=False):
        timeout = parse_int_env("WORKFLOW_POLL_TIMEOUT", 60, min_value=1)
        deadline = time.monotonic() + timeout
        log(f"Polling workflow start for up to {timeout} seconds.")
        while time.monotonic() < deadline:
            run = find_run_started_after(get_recent_workflow_runs(token, owner, repo, workflow_id, ref), dispatched_at)
            if run:
                log(f"Workflow run started: {run.get('html_url', 'URL unavailable')}")
                return run
            time.sleep(5)
        log("Workflow dispatch was accepted, but no new run was observed before timeout.")
        return None

    wait_seconds = parse_int_env("DISPATCH_WAIT_SECONDS", 30, min_value=0)
    if wait_seconds:
        log(f"Waiting {wait_seconds} seconds after workflow dispatch.")
        time.sleep(wait_seconds)

    try:
        run = find_run_started_after(get_recent_workflow_runs(token, owner, repo, workflow_id, ref), dispatched_at)
    except ScriptError as exc:
        log(f"Workflow dispatch was accepted, but run status could not be checked: {exc}")
        return None

    if run:
        log(f"Workflow run detected: {run.get('html_url', 'URL unavailable')}")
        return run
    else:
        log("Workflow dispatch was accepted, but a new run was not visible yet.")
        return None


def read_ssh_public_key() -> str:
    key = ssh_key_path()
    public_key_path = key.with_name(f"{key.name}.pub")
    if public_key_path.is_file():
        public_key = public_key_path.read_text(encoding="utf-8").strip()
        if public_key:
            return public_key

    ssh_keygen = shutil.which("ssh-keygen.exe" if os.name == "nt" else "ssh-keygen") or shutil.which("ssh-keygen")
    if not ssh_keygen:
        raise ScriptError(f"SSH public key not found at {public_key_path}, and ssh-keygen is not available to derive it.")

    try:
        result = subprocess.run(
            [ssh_keygen, "-y", "-f", str(key)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
            creationflags=windows_hidden_creationflags(),
            startupinfo=windows_hidden_startupinfo(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScriptError(f"Could not derive SSH public key from {key}: {exc}") from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or "ssh-keygen returned a non-zero exit code"
        raise ScriptError(f"Could not derive SSH public key from {key}: {detail}")

    public_key = result.stdout.strip()
    if not public_key:
        raise ScriptError(f"ssh-keygen did not return a public key for {key}.")
    return public_key


def encrypt_github_secret(public_key: str, value: str) -> str | None:
    try:
        from nacl import encoding, public
    except ImportError:
        log("PyNaCl is not installed, so GitHub Actions secret creation is skipped.")
        return None

    key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(key)
    encrypted = sealed_box.encrypt(value.encode("utf-8"))
    return base64.b64encode(encrypted).decode("ascii")


def set_actions_secret(token: str, owner: str, repo: str, name: str, value: str) -> bool:
    encoded_owner = quote(owner, safe="")
    encoded_repo = quote(repo, safe="")
    encoded_name = quote(name, safe="")
    public_key_response = github_request(
        "GET",
        f"/repos/{encoded_owner}/{encoded_repo}/actions/secrets/public-key",
        token,
        expected={200},
    )
    public_key_payload = public_key_response.json()
    key_id = public_key_payload.get("key_id")
    key = public_key_payload.get("key")
    if not isinstance(key_id, str) or not isinstance(key, str):
        raise ScriptError("GitHub did not return a repository secrets public key.")

    encrypted_value = encrypt_github_secret(key, value)
    if not encrypted_value:
        return False

    github_request(
        "PUT",
        f"/repos/{encoded_owner}/{encoded_repo}/actions/secrets/{encoded_name}",
        token,
        expected={201, 204},
        json_body={
            "encrypted_value": encrypted_value,
            "key_id": key_id,
        },
    )
    log(f"GitHub Actions secret {name} has been created/updated.")
    return True


def get_workflow_logs(token: str, owner: str, repo: str, run_id: int) -> bytes | None:
    encoded_owner = quote(owner, safe="")
    encoded_repo = quote(repo, safe="")
    path = f"/repos/{encoded_owner}/{encoded_repo}/actions/runs/{run_id}/logs"
    response = github_request("GET", path, token, expected={200, 404})
    if response.status_code == 404:
        return None
    return response.content


def extract_trycloudflare_host_from_zip(log_zip: bytes) -> str | None:
    try:
        with zipfile.ZipFile(io.BytesIO(log_zip)) as archive:
            for name in archive.namelist():
                if name.endswith("/"):
                    continue
                with archive.open(name) as handle:
                    text = handle.read().decode("utf-8", errors="replace")
                match = TRYCLOUDFLARE_RE.search(text)
                if match:
                    return match.group(1)
    except zipfile.BadZipFile:
        text = log_zip.decode("utf-8", errors="replace")
        match = TRYCLOUDFLARE_RE.search(text)
        if match:
            return match.group(1)
    return None


def extract_tunnel_info_from_zip(archive_bytes: bytes) -> TunnelInfo | None:
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            files: dict[str, str] = {}
            for name in archive.namelist():
                basename = Path(name).name
                if basename not in {"host.txt", "ssh_host_key.pub"}:
                    continue
                with archive.open(name) as handle:
                    files[basename] = handle.read(16 * 1024).decode("utf-8", errors="strict").strip()
    except (zipfile.BadZipFile, UnicodeError, OSError):
        return None

    host = files.get("host.txt", "")
    host_match = TRYCLOUDFLARE_RE.fullmatch(host)
    key = files.get("ssh_host_key.pub", "")
    key_match = SSH_HOST_KEY_RE.fullmatch(key)
    if not host_match or not key_match:
        return None
    return TunnelInfo(host=host_match.group(1).lower(), ssh_host_key=key)


def get_tunnel_info_from_artifact(token: str, owner: str, repo: str, run_id: int) -> TunnelInfo | None:
    encoded_owner = quote(owner, safe="")
    encoded_repo = quote(repo, safe="")
    artifacts_path = f"/repos/{encoded_owner}/{encoded_repo}/actions/runs/{run_id}/artifacts"
    response = github_request("GET", artifacts_path, token, expected={200})
    artifacts = response.json().get("artifacts", [])
    if not isinstance(artifacts, list):
        return None

    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        if artifact.get("name") != TUNNEL_INFO_ARTIFACT_NAME or artifact.get("expired"):
            continue
        artifact_id = artifact.get("id")
        if not isinstance(artifact_id, int):
            continue

        download_path = f"/repos/{encoded_owner}/{encoded_repo}/actions/artifacts/{artifact_id}/zip"
        archive = github_request("GET", download_path, token, expected={200}).content
        info = extract_tunnel_info_from_zip(archive)
        if info:
            return info
        raise ScriptError(
            f"Workflow run {run_id} published an incompatible tunnel-info artifact "
            "without a valid SSH host key. The run must be replaced."
        )

    return None


def wait_for_tunnel_info(token: str, owner: str, repo: str, run: dict[str, Any]) -> TunnelInfo:
    run_id = run.get("id")
    if not isinstance(run_id, int):
        raise ScriptError("Workflow run was detected, but its run id is missing.")

    timeout = parse_int_env("TUNNEL_URL_TIMEOUT", TUNNEL_URL_TIMEOUT, min_value=1)
    deadline = time.monotonic() + timeout
    log(f"Waiting for trycloudflare hostname in workflow artifact for up to {timeout} seconds.")

    while time.monotonic() < deadline:
        info = get_tunnel_info_from_artifact(token, owner, repo, run_id)
        if info:
            log(f"Detected Cloudflare tunnel host and authenticated SSH host key: {info.host}")
            return info
        time.sleep(5)

    raise ScriptError(
        "Could not find a valid trycloudflare.com hostname and SSH host key in the workflow artifact. "
        f"Check the run manually: {run.get('html_url', 'URL unavailable')}"
    )


def run_version_check(binary: str) -> bool:
    try:
        result = subprocess.run(
            [binary, "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
            creationflags=windows_hidden_creationflags(),
            startupinfo=windows_hidden_startupinfo(),
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def existing_cloudflared() -> str | None:
    name = "cloudflared.exe" if os.name == "nt" else "cloudflared"
    if os.name == "nt":
        private_binary = runtime_dir() / "bin" / name
        if private_binary.is_file() and run_version_check(str(private_binary)):
            log(f"cloudflared is already available at {private_binary}.")
            return str(private_binary)
        return None

    binary = shutil.which(name) or shutil.which("cloudflared")
    if binary and run_version_check(binary):
        log(f"cloudflared is already available at {binary}.")
        return binary
    return None


def cloudflared_asset_candidates() -> list[str]:
    system = platform.system().lower()
    machine = platform.machine().lower()

    if machine in {"x86_64", "amd64"}:
        arch = "amd64"
    elif machine in {"aarch64", "arm64"}:
        arch = "arm64"
    elif machine.startswith("arm"):
        arch = "arm"
    elif machine in {"i386", "i686", "x86"}:
        arch = "386"
    else:
        raise ScriptError(f"Unsupported CPU architecture for cloudflared auto-install: {machine}")

    if system == "linux":
        return [f"cloudflared-linux-{arch}"]
    if system == "darwin":
        return [f"cloudflared-darwin-{arch}.tgz", f"cloudflared-darwin-{arch}"]
    if system == "windows":
        if arch != "amd64":
            raise ScriptError(f"Unsupported Windows architecture for cloudflared auto-install: {machine}")
        return ["cloudflared-windows-amd64.exe"]

    raise ScriptError(f"Unsupported OS for cloudflared auto-install: {system}")


def fetch_latest_cloudflared_release() -> dict[str, Any]:
    url = "https://api.github.com/repos/cloudflare/cloudflared/releases/latest"
    try:
        response = requests.get(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "cloudflare-proxy-bootstrap/1.0",
            },
            timeout=HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise ScriptError(f"Network error while fetching latest cloudflared release: {exc}") from exc

    if response.status_code != 200:
        raise ScriptError(f"Could not fetch latest cloudflared release: HTTP {response.status_code}: {github_error(response)}")
    return response.json()


def select_cloudflared_asset(release: dict[str, Any]) -> dict[str, Any]:
    assets = release.get("assets", [])
    if not isinstance(assets, list):
        raise ScriptError("cloudflared release response does not contain an assets list.")

    assets_by_name = {asset.get("name"): asset for asset in assets if isinstance(asset, dict)}
    for candidate in cloudflared_asset_candidates():
        asset = assets_by_name.get(candidate)
        if asset and asset.get("browser_download_url"):
            return asset

    available = ", ".join(sorted(name for name in assets_by_name if name))
    raise ScriptError(f"No suitable cloudflared asset found for this platform. Available assets: {available}")


def download_file(url: str, destination: Path) -> None:
    try:
        with requests.get(url, stream=True, timeout=HTTP_TIMEOUT, headers={"User-Agent": "cloudflare-proxy-bootstrap/1.0"}) as response:
            if response.status_code != 200:
                raise ScriptError(f"Download failed with HTTP {response.status_code}: {github_error(response)}")
            with destination.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        handle.write(chunk)
    except requests.RequestException as exc:
        raise ScriptError(f"Network error while downloading {url}: {exc}") from exc


def safe_extract_tar(archive: Path, destination: Path) -> None:
    with tarfile.open(archive) as tar:
        destination_resolved = destination.resolve()
        for member in tar.getmembers():
            target = (destination / member.name).resolve()
            if destination_resolved not in target.parents and target != destination_resolved:
                raise ScriptError(f"Unsafe path in tar archive: {member.name}")
        tar.extractall(destination)


def unpack_cloudflared(downloaded: Path, asset_name: str, workdir: Path) -> Path:
    if asset_name.endswith((".tgz", ".tar.gz")):
        extract_dir = workdir / "extract"
        extract_dir.mkdir()
        safe_extract_tar(downloaded, extract_dir)
        for path in extract_dir.rglob("*"):
            if path.is_file() and path.name in {"cloudflared", "cloudflared.exe"}:
                return path
        raise ScriptError(f"Could not find cloudflared binary inside {asset_name}.")

    if asset_name.endswith(".zip"):
        extract_dir = workdir / "extract"
        extract_dir.mkdir()
        with zipfile.ZipFile(downloaded) as archive:
            archive.extractall(extract_dir)
        for path in extract_dir.rglob("*"):
            if path.is_file() and path.name in {"cloudflared", "cloudflared.exe"}:
                return path
        raise ScriptError(f"Could not find cloudflared binary inside {asset_name}.")

    return downloaded


def is_writable_directory(path: Path) -> bool:
    return path.is_dir() and os.access(path, os.W_OK | os.X_OK)


def path_entries() -> list[Path]:
    entries: list[Path] = []
    for raw in os.getenv("PATH", "").split(os.pathsep):
        if not raw:
            continue
        try:
            entries.append(Path(raw).expanduser().resolve())
        except OSError:
            continue
    return entries


def choose_install_dir() -> Path:
    requested = os.getenv("CLOUDFLARED_INSTALL_DIR")
    if requested:
        directory = expand_path(requested)
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ScriptError(f"Could not create CLOUDFLARED_INSTALL_DIR {directory}: {exc}") from exc
        if not is_writable_directory(directory):
            raise ScriptError(f"CLOUDFLARED_INSTALL_DIR is not writable: {directory}")
        return directory

    if os.name == "nt":
        directory = runtime_dir() / "bin"
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ScriptError(f"Could not create cloudflared install directory {directory}: {exc}") from exc
        return directory

    path_dirs = path_entries()
    preferred = Path("/usr/local/bin").resolve() if os.name != "nt" else None
    if preferred and preferred in path_dirs and is_writable_directory(preferred):
        return preferred

    for directory in path_dirs:
        if is_writable_directory(directory):
            return directory

    fallback = (Path.home() / ".local" / "bin").resolve()
    try:
        fallback.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ScriptError(f"Could not create fallback install directory {fallback}: {exc}") from exc
    if not is_writable_directory(fallback):
        raise ScriptError(f"No writable directory found for cloudflared installation. Tried fallback {fallback}.")
    if fallback not in path_dirs:
        log(f"Warning: installing cloudflared to {fallback}, which is not in PATH. The script will use its absolute path.")
    return fallback


def install_cloudflared() -> str:
    log("cloudflared is not available. Installing latest release.")
    release = fetch_latest_cloudflared_release()
    asset = select_cloudflared_asset(release)
    asset_name = str(asset["name"])
    download_url = str(asset["browser_download_url"])
    executable_name = "cloudflared.exe" if os.name == "nt" else "cloudflared"
    install_dir = choose_install_dir()
    target = install_dir / executable_name

    with tempfile.TemporaryDirectory(prefix="cloudflared-install-") as temp_name:
        temp_dir = Path(temp_name)
        downloaded = temp_dir / asset_name
        log(f"Downloading {asset_name}.")
        download_file(download_url, downloaded)
        binary = unpack_cloudflared(downloaded, asset_name, temp_dir)
        try:
            shutil.copy2(binary, target)
        except OSError as exc:
            raise ScriptError(f"Could not install cloudflared to {target}: {exc}") from exc

    if os.name != "nt":
        try:
            mode = target.stat().st_mode
            target.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except OSError as exc:
            raise ScriptError(f"Could not make cloudflared executable at {target}: {exc}") from exc

    if not run_version_check(str(target)):
        raise ScriptError(f"Installed cloudflared at {target}, but '{target} --version' failed.")

    log(f"cloudflared installed at {target}.")
    return str(target)


def ensure_cloudflared() -> str:
    return existing_cloudflared() or install_cloudflared()


def ensure_ssh_binary() -> str:
    ssh = shutil.which("ssh.exe" if os.name == "nt" else "ssh") or shutil.which("ssh")
    if not ssh:
        raise ScriptError("OpenSSH client 'ssh' was not found in PATH.")
    return ssh


def generate_ssh_key(path: Path) -> None:
    ssh_keygen = shutil.which("ssh-keygen.exe" if os.name == "nt" else "ssh-keygen") or shutil.which("ssh-keygen")
    if not ssh_keygen:
        raise ScriptError(f"SSH private key not found: {path}, and ssh-keygen is not available to create it.")

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ScriptError(f"Could not create SSH key directory {path.parent}: {exc}") from exc

    log(f"SSH private key not found. Generating a new key at {path}.")
    try:
        result = subprocess.run(
            [ssh_keygen, "-t", "rsa", "-b", "4096", "-N", "", "-f", str(path), "-C", "cloudflare-proxy"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
            creationflags=windows_hidden_creationflags(),
            startupinfo=windows_hidden_startupinfo(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScriptError(f"Could not generate SSH key at {path}: {exc}") from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "ssh-keygen returned a non-zero exit code"
        raise ScriptError(f"Could not generate SSH key at {path}: {detail}")


def ssh_key_path() -> Path:
    raw = os.getenv("SSH_KEY_PATH", "~/.ssh/id_rsa")
    path = expand_path(raw)
    if not path.is_file():
        generate_ssh_key(path)
    if not path.is_file():
        raise ScriptError(f"SSH private key not found: {path}. Set SSH_KEY_PATH to the correct key.")
    return path


def tail_file(path: Path, max_chars: int = 4000) -> str:
    try:
        data = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return data[-max_chars:]


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise OSError("socket closed before enough data was received")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def probe_socks5_handshake(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"\x05\x01\x00")
            return sock.recv(2) == b"\x05\x00"
    except OSError:
        return False


def proxy_test_target() -> tuple[str, int]:
    host = os.getenv("PROXY_TEST_HOST", DEFAULT_PROXY_TEST_HOST).strip()
    if not host:
        host = DEFAULT_PROXY_TEST_HOST
    port = parse_port_env("PROXY_TEST_PORT", DEFAULT_PROXY_TEST_PORT)
    return host, port


def probe_socks5(host: str, port: int, timeout: float = 5.0) -> bool:
    target_host, target_port = proxy_test_target()
    encoded_host = target_host.encode("idna")
    if len(encoded_host) > 255:
        return False

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"\x05\x01\x00")
            if recv_exact(sock, 2) != b"\x05\x00":
                return False

            request = (
                b"\x05\x01\x00\x03"
                + bytes([len(encoded_host)])
                + encoded_host
                + int(target_port).to_bytes(2, "big")
            )
            sock.sendall(request)
            reply = recv_exact(sock, 4)
            if reply[0] != 5 or reply[1] != 0:
                return False

            atyp = reply[3]
            if atyp == 1:
                recv_exact(sock, 4 + 2)
            elif atyp == 3:
                length = recv_exact(sock, 1)[0]
                recv_exact(sock, length + 2)
            elif atyp == 4:
                recv_exact(sock, 16 + 2)
            else:
                return False
            return True
    except OSError:
        return False


def wait_for_socks5_proxy(host: str, port: int, timeout: int = 10) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if probe_socks5(host, port, timeout=1):
            return True
        time.sleep(0.25)
    return False


def wait_for_tcp_listener(host: str, port: int, timeout: int = 10) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def cleanup_stale_ssh_tunnels(port: int, bind_host: str = DEFAULT_SOCKS_HOST) -> None:
    if os.name != "nt" or probe_socks5(socks_probe_host(bind_host), port):
        return

    endpoint = format_host_port(bind_host, port)

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-CimInstance Win32_Process | "
                    "Where-Object { $_.Name -eq 'ssh.exe' -and "
                    f"($_.CommandLine -like '*-D {port}*proxyuser@*' -or "
                    f"$_.CommandLine -like '*-D {endpoint}*proxyuser@*') }} | "
                    "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
                ),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
            check=False,
            creationflags=windows_hidden_creationflags(),
            startupinfo=windows_hidden_startupinfo(),
        )
    except (OSError, subprocess.SubprocessError):
        return

    if result.returncode == 0:
        time.sleep(0.5)


def stop_cloudflared_access_listeners(local_port: int | None = None) -> None:
    if os.name != "nt":
        return
    pattern = f"*access*--url*{DEFAULT_SOCKS_HOST}:{local_port}*" if local_port else "*access*--url*"
    try:
        subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-CimInstance Win32_Process | "
                    f"Where-Object {{ $_.Name -eq 'cloudflared.exe' -and $_.CommandLine -like '{pattern}' }} | "
                    "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
                ),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
            check=False,
            creationflags=windows_hidden_creationflags(),
            startupinfo=windows_hidden_startupinfo(),
        )
    except (OSError, subprocess.SubprocessError):
        return


def stop_ssh_tunnels(port: int | None = None) -> None:
    if os.name != "nt":
        return
    condition = (
        f"($_.CommandLine -like '*-D {port}*proxyuser@*' -or "
        f"$_.CommandLine -like '*-D *:{port}*proxyuser@*')"
        if port
        else "$_.CommandLine -like '*-D *proxyuser@*'"
    )
    try:
        subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-CimInstance Win32_Process | "
                    f"Where-Object {{ $_.Name -eq 'ssh.exe' -and {condition} }} | "
                    "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
                ),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
            check=False,
            creationflags=windows_hidden_creationflags(),
            startupinfo=windows_hidden_startupinfo(),
        )
    except (OSError, subprocess.SubprocessError):
        return


def format_command_for_log(command: list[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(command)
    return shlex.join(command)


def terminate_popen(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=5)
    except (OSError, subprocess.SubprocessError):
        try:
            process.kill()
        except OSError:
            pass


def write_known_hosts(ssh_host: str, ssh_host_key: str) -> Path:
    if not SAFE_HOST_RE.fullmatch(ssh_host) or not SSH_HOST_KEY_RE.fullmatch(ssh_host_key.strip()):
        raise ScriptError("Refusing to use an invalid SSH hostname or host key.")
    path = runtime_dir() / "known_hosts"
    atomic_write_text(path, f"{ssh_host} {ssh_host_key.strip()}\n")
    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError as exc:
            raise ScriptError(f"Could not protect SSH known_hosts file {path}: {exc}") from exc
    return path


def start_cloudflared_access_listener(cloudflared: str, ssh_host: str, local_port: int) -> subprocess.Popen[Any]:
    access_mode = os.getenv("CLOUDFLARED_ACCESS_MODE", "tcp").strip().lower()
    if access_mode not in {"tcp", "ssh"}:
        raise ScriptError(f"CLOUDFLARED_ACCESS_MODE must be 'tcp' or 'ssh', got {access_mode!r}.")

    log_path = expand_path(os.getenv("CLOUDFLARED_LOG", "~/.cloudflare-proxy-cloudflared.log"))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    rotate_log(log_path)
    command = [
        cloudflared,
        "access",
        access_mode,
        "--hostname",
        ssh_host,
        "--url",
        f"{DEFAULT_SOCKS_HOST}:{local_port}",
    ]

    log(f"Starting hidden cloudflared TCP bridge on {DEFAULT_SOCKS_HOST}:{local_port}. Log: {log_path}")
    log(f"Cloudflared command: {format_command_for_log(command)}")

    log_handle = log_path.open("ab")
    popen_kwargs: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": log_handle,
        "stderr": subprocess.STDOUT,
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = windows_detached_hidden_creationflags()
        popen_kwargs["startupinfo"] = windows_hidden_startupinfo()
        popen_kwargs["close_fds"] = True
    else:
        popen_kwargs["start_new_session"] = True

    try:
        process = subprocess.Popen(command, **popen_kwargs)
    except OSError as exc:
        raise ScriptError(f"Failed to start cloudflared access listener: {exc}") from exc
    finally:
        log_handle.close()

    if not wait_for_tcp_listener(DEFAULT_SOCKS_HOST, local_port, timeout=10):
        process.poll()
        details = tail_file(log_path).strip()
        suffix = f"\ncloudflared log tail:\n{details}" if details else ""
        if process.returncode is not None:
            raise ScriptError(f"cloudflared access listener exited with code {process.returncode}.{suffix}")
        terminate_popen(process)
        raise ScriptError(f"cloudflared started, but {DEFAULT_SOCKS_HOST}:{local_port} did not begin listening.{suffix}")

    return process


def start_ssh_tunnel(cloudflared: str, tunnel_info: TunnelInfo) -> subprocess.Popen[Any]:
    ssh = ensure_ssh_binary()
    key = ssh_key_path()
    ssh_user = os.getenv("SSH_USER", DEFAULT_SSH_USER)
    ssh_host = tunnel_info.host
    known_hosts = write_known_hosts(ssh_host, tunnel_info.ssh_host_key)
    socks_host = parse_socks_host_env()
    probe_host = socks_probe_host(socks_host)
    socks_port = parse_port_env("SOCKS_PORT", DEFAULT_SOCKS_PORT)
    local_port = parse_port_env("CLOUDFLARED_LOCAL_PORT", DEFAULT_CLOUDFLARED_LOCAL_PORT)
    log_path = expand_path(os.getenv("SSH_TUNNEL_LOG", "~/.cloudflare-proxy-ssh.log"))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    rotate_log(log_path)

    stop_cloudflared_access_listeners(local_port)
    cloudflared_process = start_cloudflared_access_listener(cloudflared, ssh_host, local_port)

    command = [
        ssh,
        "-N",
        "-D",
        format_host_port(socks_host, socks_port),
        "-p",
        str(local_port),
        "-i",
        str(key),
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "ServerAliveInterval=30",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        f"HostKeyAlias={ssh_host}",
        f"{ssh_user}@{DEFAULT_SOCKS_HOST}",
    ]

    log(f"Starting SSH SOCKS5 tunnel on {format_host_port(socks_host, socks_port)}. SSH log: {log_path}")
    log(f"SSH command: {format_command_for_log(command)}")
    log_handle = log_path.open("ab")
    popen_kwargs: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": log_handle,
        "stderr": subprocess.STDOUT,
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = windows_detached_hidden_creationflags()
        popen_kwargs["startupinfo"] = windows_hidden_startupinfo()
        popen_kwargs["close_fds"] = True
    else:
        popen_kwargs["start_new_session"] = True

    try:
        process = subprocess.Popen(command, **popen_kwargs)
    except OSError as exc:
        terminate_popen(cloudflared_process)
        raise ScriptError(f"Failed to start SSH tunnel: {exc}") from exc
    finally:
        log_handle.close()

    startup_timeout = parse_int_env("SSH_STARTUP_TIMEOUT", 45, min_value=10)
    if not wait_for_socks5_proxy(probe_host, socks_port, timeout=startup_timeout):
        process.poll()
        details = tail_file(log_path).strip()
        suffix = f"\nSSH log tail:\n{details}" if details else ""
        if process.returncode is not None:
            terminate_popen(cloudflared_process)
            raise ScriptError(f"SSH tunnel process exited with code {process.returncode}.{suffix}")
        terminate_popen(process)
        terminate_popen(cloudflared_process)
        raise ScriptError(
            f"SSH tunnel started, but {format_host_port(socks_host, socks_port)} did not answer as SOCKS5.{suffix}"
        )

    target_host, target_port = proxy_test_target()
    log(f"SOCKS5 tunnel is usable on {format_host_port(socks_host, socks_port)} -> {target_host}:{target_port}.")

    write_json_file(
        proxy_state_path(),
        {
            "ssh_pid": process.pid,
            "cloudflared_pid": cloudflared_process.pid,
            "socks_host": socks_host,
            "socks_port": socks_port,
            "local_port": local_port,
            "ssh_host": ssh_host,
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    return process


def record_recovery_failure(run_id: int) -> int:
    state = read_json_file(recovery_state_path())
    previous_id = state.get("run_id")
    try:
        previous_count = int(state.get("failures", 0))
    except (TypeError, ValueError):
        previous_count = 0
    count = previous_count + 1 if previous_id == run_id else 1
    write_json_file(
        recovery_state_path(),
        {"run_id": run_id, "failures": count, "updated_at": datetime.now(timezone.utc).isoformat()},
    )
    return count


def clear_recovery_failures() -> None:
    try:
        recovery_state_path().unlink(missing_ok=True)
    except OSError:
        pass


def ensure_proxy_once(allow_device_flow: bool = True) -> int:
    socks_host = parse_socks_host_env()
    probe_host = socks_probe_host(socks_host)
    socks_port = parse_port_env("SOCKS_PORT", DEFAULT_SOCKS_PORT)
    endpoint = f"{format_host_port(socks_host, socks_port)} socks5"
    emit_event("checking", "running", "Проверяю локальный SOCKS5-прокси", progress=5)
    proxy_is_healthy = probe_socks5(probe_host, socks_port)
    if proxy_is_healthy and not allow_device_flow:
        target_host, target_port = proxy_test_target()
        clear_recovery_failures()
        log(f"SOCKS5 proxy is already usable on {format_host_port(socks_host, socks_port)} -> {target_host}:{target_port}.")
        emit_event("ready", "success", "Прокси работает", progress=100, endpoint=endpoint)
        return socks_port
    if proxy_is_healthy:
        log("Proxy is healthy; synchronizing repository and managed workflow before returning.")
    elif probe_socks5_handshake(probe_host, socks_port):
        target_host, target_port = proxy_test_target()
        log(
            f"SOCKS5 port {format_host_port(socks_host, socks_port)} responds, "
            f"but cannot connect to {target_host}:{target_port}; restarting tunnel."
        )

    if not proxy_is_healthy:
        emit_event("recovery", "running", "Очищаю старые локальные процессы", progress=10)
        stop_owned_proxy_processes()
        cleanup_stale_ssh_tunnels(socks_port, socks_host)

    emit_event("github", "running", "Проверяю авторизацию GitHub", progress=18)
    token = get_github_token(allow_device_flow=allow_device_flow)
    owner = get_authenticated_user(token)
    emit_event("repository", "running", "Проверяю публичный репозиторий", progress=28)
    repository = ensure_repository(token, owner, REPO_NAME)

    workflow_id = os.getenv("GITHUB_WORKFLOW_ID", DEFAULT_WORKFLOW_ID)
    default_branch = repository.get("default_branch")
    if not isinstance(default_branch, str) or not default_branch:
        raise ScriptError(f"GitHub did not return a default branch for {owner}/{REPO_NAME}.")
    ref = os.getenv("GITHUB_REF", "").strip() or default_branch
    emit_event("workflow", "running", "Синхронизирую GitHub Actions workflow", progress=40)
    _workflow_created, workflow_accepts_public_key = ensure_workflow_file(token, owner, REPO_NAME, workflow_id, ref)
    if proxy_is_healthy:
        target_host, target_port = proxy_test_target()
        clear_recovery_failures()
        log(f"SOCKS5 proxy remains usable on {format_host_port(socks_host, socks_port)} -> {target_host}:{target_port}.")
        emit_event("ready", "success", "Прокси работает", progress=100, endpoint=endpoint)
        return socks_port
    emit_event("runner", "running", "Ищу или запускаю GitHub runner", progress=52)
    run = get_active_workflow_run(token, owner, REPO_NAME, workflow_id, ref)

    def dispatch_new_run() -> dict[str, Any]:
        workflow_inputs = None
        if workflow_accepts_public_key:
            public_key = read_ssh_public_key()
            secret_saved = False
            try:
                secret_saved = set_actions_secret(token, owner, REPO_NAME, SSH_PUBLIC_KEY_SECRET_NAME, public_key)
            except ScriptError as exc:
                log(f"Could not create GitHub Actions secret {SSH_PUBLIC_KEY_SECRET_NAME}: {exc}")
            if not secret_saved:
                workflow_inputs = {"ssh_public_key": public_key}

        dispatched_at, dispatched_run = dispatch_workflow(token, owner, REPO_NAME, workflow_id, ref, workflow_inputs)
        detected_run = dispatched_run or wait_for_workflow_start(token, owner, REPO_NAME, workflow_id, ref, dispatched_at)
        if not detected_run:
            raise ScriptError("Workflow is expected to provide SSH_HOST, but no active workflow run was found.")
        return detected_run

    if not run:
        run = dispatch_new_run()

    emit_event("tunnel", "running", "Жду адрес Cloudflare Tunnel", progress=68)
    cloudflared = ensure_cloudflared()
    explicit_host = os.getenv("SSH_HOST", "").strip()
    try:
        if explicit_host:
            explicit_key = os.getenv("SSH_HOST_KEY", "").strip()
            if not explicit_key:
                raise ScriptError("SSH_HOST_KEY is required when SSH_HOST is supplied; insecure host-key bypass is not allowed.")
            tunnel_info = TunnelInfo(explicit_host, explicit_key)
        elif workflow_accepts_public_key:
            tunnel_info = wait_for_tunnel_info(token, owner, REPO_NAME, run)
        else:
            raise ScriptError("The selected custom workflow does not provide tunnel information. Set SSH_HOST and SSH_HOST_KEY.")
        emit_event("local", "running", "Подключаю локальный cloudflared и SSH", progress=84)
        start_ssh_tunnel(cloudflared, tunnel_info)
    except ScriptError as first_error:
        run_id = run.get("id")
        if explicit_host or not isinstance(run_id, int):
            raise
        failures = record_recovery_failure(run_id)
        threshold = parse_int_env("RUN_FAILURES_BEFORE_RESTART", 1, min_value=1)
        if failures < threshold:
            raise
        log(f"Workflow run {run_id} produced an unusable tunnel ({first_error}); replacing the run.")
        cancel_workflow_run(token, owner, REPO_NAME, run_id)
        wait_for_run_inactive(token, owner, REPO_NAME, run_id)
        replacement_run = dispatch_new_run()
        replacement_info = wait_for_tunnel_info(token, owner, REPO_NAME, replacement_run)
        stop_owned_proxy_processes()
        cleanup_stale_ssh_tunnels(socks_port, socks_host)
        start_ssh_tunnel(cloudflared, replacement_info)

    clear_recovery_failures()
    emit_event("ready", "success", "Прокси готов к работе", progress=100, endpoint=endpoint)
    return socks_port


def run_watchdog() -> int:
    write_watchdog_pid(os.getpid())
    interval = parse_int_env("WATCHDOG_INTERVAL_SECONDS", WATCHDOG_INTERVAL_SECONDS, min_value=10)
    log(f"Proxy watchdog started with PID {os.getpid()}; check interval: {interval} seconds.")

    try:
        while True:
            try:
                ensure_proxy_once(allow_device_flow=False)
            except Exception as exc:
                log(f"Watchdog health check failed: {type(exc).__name__}: {exc}")
            time.sleep(interval)
    finally:
        if read_watchdog_pid() == os.getpid():
            try:
                watchdog_pid_path().unlink(missing_ok=True)
            except OSError:
                pass


def main() -> int:
    if "--json-events" in sys.argv:
        os.environ[JSON_EVENTS_ENV] = "1"
    if "--status" in sys.argv:
        socks_host = parse_socks_host_env()
        socks_port = parse_port_env("SOCKS_PORT", DEFAULT_SOCKS_PORT)
        endpoint = f"{format_host_port(socks_host, socks_port)} socks5"
        if probe_socks5(socks_probe_host(socks_host), socks_port):
            emit_event("ready", "success", "Прокси работает", progress=100, endpoint=endpoint)
        else:
            emit_event("idle", "idle", "Прокси остановлен", progress=0)
        return 0
    if "--watchdog" in sys.argv:
        return run_watchdog()
    if "--stop" in sys.argv:
        local_port = parse_port_env("CLOUDFLARED_LOCAL_PORT", DEFAULT_CLOUDFLARED_LOCAL_PORT)
        socks_port = parse_port_env("SOCKS_PORT", DEFAULT_SOCKS_PORT)
        stop_watchdog_process()
        stop_duplicate_watchdogs(exclude_pid=os.getpid())
        stop_owned_proxy_processes()
        # One-time compatibility cleanup for processes created by older script versions.
        stop_ssh_tunnels(socks_port)
        stop_cloudflared_access_listeners(local_port)
        emit_event("stopped", "success", "Прокси остановлен", progress=0)
        return 0

    socks_port = ensure_proxy_once(allow_device_flow=True)
    start_watchdog_if_needed(restart=True)

    print(f"{parse_socks_host_env()} {socks_port} socks5")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ScriptError as exc:
        emit_event("error", "error", str(exc))
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("ERROR: Interrupted by user.", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        report = write_crash_report()
        emit_event("error", "error", f"Unexpected {type(exc).__name__}: {exc}")
        print(f"ERROR: Unexpected {type(exc).__name__}: {exc}. Details: {report}", file=sys.stderr)
        raise SystemExit(1)

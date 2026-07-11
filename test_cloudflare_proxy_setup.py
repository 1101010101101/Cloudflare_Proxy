import base64
import io
import json
import os
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import cloudflare_proxy_setup as proxy


class FakeResponse:
    def __init__(self, status_code=200, payload=None, headers=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.headers = headers or {}
        self.text = ""
        self.reason = ""
        self.content = b""

    def json(self):
        return self._payload


def artifact_zip(host="example-name.trycloudflare.com", key=None):
    key = key or "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey cloudflare-proxy"
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("host.txt", host + "\n")
        archive.writestr("ssh_host_key.pub", key + "\n")
    return output.getvalue()


class ConfigurationTests(unittest.TestCase):
    def test_port_range_is_enforced(self):
        with mock.patch.dict(os.environ, {"SOCKS_PORT": "65536"}):
            with self.assertRaisesRegex(proxy.ScriptError, "<= 65535"):
                proxy.parse_port_env("SOCKS_PORT", 1081)

    def test_custom_socks_bind_address_is_validated(self):
        with mock.patch.dict(os.environ, {"SOCKS_HOST": "192.168.1.25"}):
            self.assertEqual(proxy.parse_socks_host_env(), "192.168.1.25")

    def test_invalid_socks_bind_address_is_rejected(self):
        with mock.patch.dict(os.environ, {"SOCKS_HOST": "all interfaces"}):
            with self.assertRaisesRegex(proxy.ScriptError, "must be an IP address"):
                proxy.parse_socks_host_env()

    def test_wildcard_bind_uses_loopback_for_health_checks(self):
        self.assertEqual(proxy.socks_probe_host("0.0.0.0"), "127.0.0.1")

    def test_invalid_boolean_is_user_facing(self):
        with self.assertRaises(proxy.ScriptError):
            proxy.parse_bool("sometimes")

    def test_json_progress_event_is_machine_readable(self):
        output = io.StringIO()
        with mock.patch.dict(os.environ, {proxy.JSON_EVENTS_ENV: "1"}):
            with redirect_stdout(output):
                proxy.emit_event(
                    "github_auth",
                    "action_required",
                    "Подтвердите вход",
                    progress=20,
                    auth_code="ABCD-1234",
                    auth_url="https://github.com/login/device",
                )
        event = json.loads(output.getvalue())
        self.assertEqual(event["type"], "proxy_event")
        self.assertEqual(event["stage"], "github_auth")
        self.assertEqual(event["progress"], 20)
        self.assertEqual(event["auth_code"], "ABCD-1234")
        self.assertEqual(event["auth_url"], "https://github.com/login/device")

    def test_managed_workflow_contains_health_and_security_controls(self):
        workflow = proxy.default_workflow_content()
        self.assertIn(f"cloudflare-proxy-managed-version: {proxy.MANAGED_WORKFLOW_VERSION}", workflow)
        self.assertIn("ssh_host_key.pub", workflow)
        self.assertIn("StrictHostKeyChecking", Path(proxy.__file__).read_text(encoding="utf-8"))
        self.assertIn("while pgrep -f", workflow)
        self.assertNotIn("SSH_PUBLIC_KEY='${{", workflow)
        self.assertIn("actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", workflow)

    def test_windows_command_line_survives_cyrillic_output(self):
        command_line = r'C:\Python314\python.exe "C:\Users\soleg\Desktop\ии\cloudflare_proxy_setup.py"'
        encoded = base64.b64encode(command_line.encode("utf-16-le")).decode("ascii")
        completed = proxy.subprocess.CompletedProcess([], 0, stdout=encoded, stderr=None)

        with mock.patch.object(proxy.os, "name", "nt"):
            with mock.patch.object(proxy.subprocess, "run", return_value=completed):
                self.assertEqual(proxy.process_command_line(123), command_line)

    def test_windows_command_line_handles_missing_stdout(self):
        completed = proxy.subprocess.CompletedProcess([], 0, stdout=None, stderr=None)

        with mock.patch.object(proxy.os, "name", "nt"):
            with mock.patch.object(proxy.subprocess, "run", return_value=completed):
                self.assertIsNone(proxy.process_command_line(123))


class ArtifactTests(unittest.TestCase):
    def test_valid_tunnel_artifact(self):
        info = proxy.extract_tunnel_info_from_zip(artifact_zip())
        self.assertIsNotNone(info)
        self.assertEqual(info.host, "example-name.trycloudflare.com")
        self.assertTrue(info.ssh_host_key.startswith("ssh-ed25519 "))

    def test_artifact_without_host_key_is_rejected(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("host.txt", "example-name.trycloudflare.com\n")
        self.assertIsNone(proxy.extract_tunnel_info_from_zip(output.getvalue()))

    def test_non_trycloudflare_artifact_host_is_rejected(self):
        self.assertIsNone(proxy.extract_tunnel_info_from_zip(artifact_zip(host="attacker.example")))

    def test_known_hosts_is_written_to_private_runtime_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(proxy, "runtime_dir", return_value=Path(temporary)):
                path = proxy.write_known_hosts(
                    "example-name.trycloudflare.com",
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey",
                )
                self.assertEqual(
                    path.read_text(encoding="utf-8"),
                    "example-name.trycloudflare.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey\n",
                )


class GithubSafetyTests(unittest.TestCase):
    def test_existing_private_repository_is_never_made_public_implicitly(self):
        response = FakeResponse(payload={"private": True, "default_branch": "main"})
        with mock.patch.object(proxy, "github_request", return_value=response) as request:
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(proxy.ScriptError, "will not change"):
                    proxy.ensure_repository("token", "owner", "cloudflare-proxy")
        request.assert_called_once()

    def test_visibility_change_requires_explicit_switch(self):
        existing = FakeResponse(payload={"private": True, "default_branch": "main"})
        changed = FakeResponse(payload={"private": False, "default_branch": "main"})
        with mock.patch.object(proxy, "github_request", side_effect=[existing, changed]) as request:
            with mock.patch.dict(os.environ, {"GITHUB_REPO_ALLOW_VISIBILITY_CHANGE": "true"}, clear=True):
                result = proxy.ensure_repository("token", "owner", "cloudflare-proxy")
        self.assertFalse(result["private"])
        self.assertEqual(request.call_count, 2)

    def test_active_run_lookup_does_not_convert_api_failure_to_no_run(self):
        with mock.patch.object(proxy, "get_recent_workflow_runs", side_effect=proxy.ScriptError("offline")):
            with self.assertRaisesRegex(proxy.ScriptError, "offline"):
                proxy.get_active_workflow_run("token", "owner", "repo", "deploy.yml", "main")

    def test_current_dispatch_response_returns_run_id_without_poll_race(self):
        response = FakeResponse(
            payload={
                "workflow_run_id": 123,
                "html_url": "https://github.com/owner/repo/actions/runs/123",
            }
        )
        with mock.patch.object(proxy, "github_request", return_value=response):
            _created_at, run = proxy.dispatch_workflow("token", "owner", "repo", "deploy.yml", "main")
        self.assertEqual(run["id"], 123)


if __name__ == "__main__":
    unittest.main()

using System.Diagnostics;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;

namespace CloudflareProxyApp;

public sealed class ProxyController : IDisposable
{
    private Process? _process;
    private string _socksHost = "127.0.0.1";
    private int _socksPort = 1081;

    public bool IsBusy => _process is { HasExited: false };

    public void ConfigureEndpoint(string host, int port)
    {
        if (IsBusy)
            throw new InvalidOperationException("Нельзя менять адрес во время выполняющейся операции.");
        _socksHost = host;
        _socksPort = port;
    }

    public async Task<int> RunAsync(
        string arguments,
        Action<ProxyEvent> onEvent,
        Action<string> onLog,
        CancellationToken cancellationToken = default)
    {
        if (IsBusy)
            throw new InvalidOperationException("Другая операция уже выполняется.");

        if (!RuntimeBootstrapper.IsReady && arguments.IndexOf("--status", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            onEvent(new ProxyEvent("idle", "idle", "Прокси остановлен", 0, null));
            return 0;
        }
        if (!RuntimeBootstrapper.IsReady && arguments.IndexOf("--stop", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            onEvent(new ProxyEvent("stopped", "success", "Прокси остановлен", 0, null));
            return 0;
        }

        await RuntimeBootstrapper.EnsureAsync(
            (progress, message) => onEvent(new ProxyEvent("runtime", "running", message, progress, null)),
            cancellationToken);
        var script = RuntimeBootstrapper.BackendPath;
        var python = RuntimeBootstrapper.PythonPath;
        var startInfo = new ProcessStartInfo
        {
            FileName = python,
            Arguments = $"\"{script}\" {arguments}",
            WorkingDirectory = Path.GetDirectoryName(script)!,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        startInfo.EnvironmentVariables["PYTHONUTF8"] = "1";
        startInfo.EnvironmentVariables["SOCKS_HOST"] = _socksHost;
        startInfo.EnvironmentVariables["SOCKS_PORT"] = _socksPort.ToString(System.Globalization.CultureInfo.InvariantCulture);
        startInfo.EnvironmentVariables["PATH"] = RuntimeBootstrapper.BuildPathEnvironment();

        _process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
        if (!_process.Start())
            throw new InvalidOperationException("Не удалось запустить Python backend.");

        using var registration = cancellationToken.Register(() =>
        {
            try
            {
                if (_process is { HasExited: false })
                    _process.Kill();
            }
            catch
            {
                // Best-effort cancellation during app shutdown.
            }
        });

        var stdoutTask = ReadLinesAsync(_process.StandardOutput, line =>
        {
            var parsed = ParseEvent(line);
            if (parsed is not null)
                onEvent(parsed);
            else if (!string.IsNullOrWhiteSpace(line))
                onLog(line);
        });
        var stderrTask = ReadLinesAsync(_process.StandardError, onLog);

        await Task.WhenAll(WaitForExitAsync(_process, cancellationToken), stdoutTask, stderrTask);
        var exitCode = _process.ExitCode;
        _process.Dispose();
        _process = null;
        return exitCode;
    }

    private static async Task ReadLinesAsync(StreamReader reader, Action<string> callback)
    {
        while (await reader.ReadLineAsync() is { } line)
            callback(line);
    }

    private static ProxyEvent? ParseEvent(string line)
    {
        try
        {
            var root = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(line);
            if (root == null || !root.TryGetValue("type", out var type) || !Equals(type, "proxy_event"))
                return null;

            return new ProxyEvent(
                root.TryGetValue("stage", out var stage) ? Convert.ToString(stage) ?? "unknown" : "unknown",
                root.TryGetValue("status", out var status) ? Convert.ToString(status) ?? "running" : "running",
                root.TryGetValue("message", out var message) ? Convert.ToString(message) ?? "" : "",
                root.TryGetValue("progress", out var progress) && progress != null ? Convert.ToInt32(progress) : null,
                root.TryGetValue("endpoint", out var endpoint) ? Convert.ToString(endpoint) : null,
                root.TryGetValue("auth_code", out var authCode) ? Convert.ToString(authCode) : null,
                root.TryGetValue("auth_url", out var authUrl) ? Convert.ToString(authUrl) : null);
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static Task WaitForExitAsync(Process process, CancellationToken cancellationToken)
    {
        var completion = new TaskCompletionSource<object?>();
        process.Exited += (_, _) => completion.TrySetResult(null);
        if (process.HasExited)
            completion.TrySetResult(null);
        cancellationToken.Register(() => completion.TrySetCanceled());
        return completion.Task;
    }

    private static string FindBackendScript()
    {
        var configured = Environment.GetEnvironmentVariable("CLOUDFLARE_PROXY_SCRIPT");
        if (!string.IsNullOrWhiteSpace(configured) && File.Exists(configured))
            return Path.GetFullPath(configured);

        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; depth < 7 && directory is not null; depth++, directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "cloudflare_proxy_setup.py");
            if (File.Exists(candidate))
                return candidate;
        }

        throw new FileNotFoundException(
            "Не найден cloudflare_proxy_setup.py. Задайте путь в CLOUDFLARE_PROXY_SCRIPT.");
    }

    private static string FindPython(string script)
    {
        var configured = Environment.GetEnvironmentVariable("CLOUDFLARE_PROXY_PYTHON");
        if (!string.IsNullOrWhiteSpace(configured))
            return configured;

        var scriptDirectory = new DirectoryInfo(Path.GetDirectoryName(script)!);
        var candidates = new[]
        {
            Path.Combine(scriptDirectory.FullName, ".venv", "Scripts", "python.exe"),
            scriptDirectory.Parent is null
                ? string.Empty
                : Path.Combine(scriptDirectory.Parent.FullName, ".venv", "Scripts", "python.exe"),
        };
        return candidates.FirstOrDefault(File.Exists) ?? "python.exe";
    }

    public void Dispose()
    {
        try
        {
            if (_process is { HasExited: false })
                _process.Kill();
        }
        catch
        {
            // The process may already be gone.
        }
        _process?.Dispose();
    }
}

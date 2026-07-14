using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace CloudflareProxyApp;

public static class TrafficRoutingModes
{
    public const string Whitelist = "whitelist";
    public const string Blacklist = "blacklist";
}

public sealed class TrafficRoutingStatus
{
    public string Session { get; set; } = "";
    public string State { get; set; } = "stopped";
    public string Message { get; set; } = "Трафик идёт напрямую";
    public int EnginePid { get; set; }
}

public static class TrafficApplicationList
{
    private static readonly char[] Separators = { '\r', '\n', ';', ',' };

    public static IReadOnlyList<string> Parse(string? value) =>
        (value ?? "")
        .Split(Separators, StringSplitOptions.RemoveEmptyEntries)
        .Select(item => item.Trim().Trim('"'))
        .Where(item => item.Length > 0)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Take(100)
        .ToArray();

    public static string Normalize(string? value) => string.Join(Environment.NewLine, Parse(value));
}

public static class TrafficRoutingRuntime
{
    public const string Version = "1.13.14";
    private const string DownloadUrl =
        "https://github.com/SagerNet/sing-box/releases/download/v1.13.14/sing-box-1.13.14-windows-amd64.zip";
    private const string ExpectedSha256 =
        "F580782C6DD10F7691C66CEA1D7C421813C5FBF7E305D1EE7CE0C3A40D196341";
    private static readonly SemaphoreSlim InstallLock = new(1, 1);

    public static string EngineDirectory => Path.Combine(RuntimeBootstrapper.RuntimeRoot, "sing-box-" + Version);
    public static string EnginePath => Path.Combine(EngineDirectory, "sing-box.exe");
    private static string MarkerPath => Path.Combine(EngineDirectory, ".verified-sha256");

    public static bool IsReady
    {
        get
        {
            try
            {
                return File.Exists(EnginePath) && File.Exists(MarkerPath) &&
                       string.Equals(File.ReadAllText(MarkerPath).Trim(), ExpectedSha256,
                           StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }
    }

    public static async Task EnsureAsync(Action<int, string> progress, CancellationToken cancellationToken)
    {
        await InstallLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (IsReady)
            {
                progress(100, "Движок маршрутизации готов");
                return;
            }

            Directory.CreateDirectory(RuntimeBootstrapper.RuntimeRoot);
            var archive = Path.Combine(RuntimeBootstrapper.RuntimeRoot, "sing-box-download.tmp");
            var work = Path.Combine(RuntimeBootstrapper.RuntimeRoot, "sing-box-installing");
            DeleteDirectorySafe(work);
            Directory.CreateDirectory(work);
            try
            {
                progress(2, "Скачиваю движок маршрутизации " + Version);
                await DownloadAsync(archive, progress, cancellationToken).ConfigureAwait(false);
                progress(88, "Проверяю SHA-256 движка");
                VerifySha256(archive);
                cancellationToken.ThrowIfCancellationRequested();

                SafeExtractZip(archive, work);
                var engine = Directory.GetFiles(work, "sing-box.exe", SearchOption.AllDirectories)
                    .FirstOrDefault() ?? throw new InvalidOperationException("В архиве отсутствует sing-box.exe.");
                var sourceDirectory = Path.GetDirectoryName(engine)!;
                VerifyProcess(engine, "version", "Не удалось проверить sing-box");

                DeleteDirectorySafe(EngineDirectory);
                MoveDirectoryWithRetry(sourceDirectory, EngineDirectory);
                File.WriteAllText(MarkerPath, ExpectedSha256 + Environment.NewLine, Encoding.ASCII);
                progress(100, "Маршрутизатор установлен");
            }
            finally
            {
                TryDeleteFile(archive);
                DeleteDirectorySafe(work);
            }
        }
        finally
        {
            InstallLock.Release();
        }
    }

    private static async Task DownloadAsync(string destination, Action<int, string> progress,
        CancellationToken cancellationToken)
    {
        ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
        using var client = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        using var response = await client.GetAsync(DownloadUrl, HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var total = response.Content.Headers.ContentLength;
        using var input = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
        using var output = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None, 81920, true);
        var buffer = new byte[81920];
        long received = 0;
        var lastProgress = -1;
        while (true)
        {
            var count = await input.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
            if (count == 0)
                break;
            await output.WriteAsync(buffer, 0, count, cancellationToken).ConfigureAwait(false);
            received += count;
            if (!total.HasValue || total.Value <= 0)
                continue;
            var current = 2 + (int)Math.Min(84, received * 84 / total.Value);
            if (current == lastProgress)
                continue;
            lastProgress = current;
            progress(current, "Скачиваю движок маршрутизации");
        }
    }

    private static void VerifySha256(string path)
    {
        using var sha = SHA256.Create();
        using var stream = File.OpenRead(path);
        var actual = BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "");
        if (!string.Equals(actual, ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Архив маршрутизатора не прошёл проверку SHA-256.");
    }

    private static void SafeExtractZip(string archivePath, string destination)
    {
        var root = Path.GetFullPath(destination).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        using var archive = ZipFile.OpenRead(archivePath);
        foreach (var entry in archive.Entries)
        {
            var target = Path.GetFullPath(Path.Combine(destination, entry.FullName));
            if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Обнаружен небезопасный путь в архиве маршрутизатора.");
            if (string.IsNullOrEmpty(entry.Name))
            {
                Directory.CreateDirectory(target);
                continue;
            }
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            entry.ExtractToFile(target, true);
        }
    }

    internal static void VerifyProcess(string executable, string arguments, string errorPrefix)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException(errorPrefix + ".");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        if (!process.WaitForExit(30000))
        {
            try { process.Kill(); } catch { }
            throw new InvalidOperationException(errorPrefix + ": превышено время ожидания.");
        }
        if (process.ExitCode != 0)
            throw new InvalidOperationException(errorPrefix + ": " + (error.Trim().Length > 0 ? error.Trim() : output.Trim()));
    }

    private static void DeleteDirectorySafe(string path)
    {
        var root = Path.GetFullPath(RuntimeBootstrapper.RuntimeRoot).TrimEnd(Path.DirectorySeparatorChar) +
                   Path.DirectorySeparatorChar;
        var target = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Отказ от удаления каталога вне runtime.");
        if (Directory.Exists(path))
            Directory.Delete(path, true);
    }

    private static void MoveDirectoryWithRetry(string source, string destination)
    {
        Exception? lastError = null;
        for (var attempt = 0; attempt < 8; attempt++)
        {
            try
            {
                Directory.Move(source, destination);
                return;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                lastError = exception;
                Thread.Sleep(250 * (attempt + 1));
            }
        }
        throw new IOException("Не удалось завершить установку движка маршрутизации.", lastError);
    }

    private static void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}

public static class TrafficRoutingConfig
{
    private static readonly JavaScriptSerializer Serializer = new() { MaxJsonLength = 1024 * 1024 };
    private static readonly string[] ProtectedProcesses =
    {
        "CloudflareProxy.exe", "sing-box.exe", "python.exe", "pythonw.exe", "ssh.exe", "cloudflared.exe"
    };
    private static readonly string[] KernelBypassNetworks =
    {
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
        "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
    };

    public static string Build(AppSettings settings, string proxyHost, int proxyPort)
    {
        var configuredList = settings.TrafficRoutingMode == TrafficRoutingModes.Whitelist
            ? settings.TrafficProxyApplications
            : settings.TrafficDirectApplications;
        var entries = TrafficApplicationList.Parse(configuredList);
        // Match a selected executable by both its full path and file name.  The name
        // keeps rules working when an application updates into a new directory.
        var names = entries.Select(Path.GetFileName)
            .Where(item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var paths = entries.Where(Path.IsPathRooted).Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (settings.TrafficRoutingMode == TrafficRoutingModes.Whitelist && names.Length == 0 && paths.Length == 0)
            throw new InvalidOperationException("Для белого списка добавьте хотя бы одно приложение.");

        var rules = new List<object>
        {
            RouteRule(new Dictionary<string, object> { ["process_name"] = ProtectedProcesses }, "direct"),
            RouteRule(new Dictionary<string, object> { ["process_path_regex"] = new[] { "(?i)^C:\\\\Windows\\\\" } }, "direct"),
        };

        if (settings.TrafficRoutingMode == TrafficRoutingModes.Blacklist)
        {
            AddApplicationRules(rules, names, paths, null, null, "direct");
        }

        rules.Add(RouteRule(new Dictionary<string, object> { ["ip_is_private"] = true }, "direct"));
        rules.Add(RouteRule(new Dictionary<string, object>
            { ["network"] = new[] { "tcp", "udp" }, ["port"] = 53 }, "direct"));
        rules.Add(RouteRule(new Dictionary<string, object> { ["network"] = "icmp" }, "direct"));

        if (settings.TrafficRoutingMode == TrafficRoutingModes.Whitelist)
        {
            AddApplicationRules(rules, names, paths, "udp", 443, "block");
            AddApplicationRules(rules, names, paths, "tcp", null, "proxy");
        }
        else
        {
            rules.Add(RouteRule(new Dictionary<string, object> { ["network"] = "udp", ["port"] = 443 }, "block"));
            rules.Add(RouteRule(new Dictionary<string, object> { ["network"] = "udp" }, "direct"));
        }

        var root = new Dictionary<string, object>
        {
            ["log"] = new Dictionary<string, object> { ["level"] = "warn", ["timestamp"] = true },
            ["inbounds"] = new object[]
            {
                new Dictionary<string, object>
                {
                    ["type"] = "tun", ["tag"] = "tun-in", ["interface_name"] = "CloudflareProxy",
                    ["address"] = new[] { "172.19.0.1/30", "fdfe:dcba:9876::1/126" },
                    ["mtu"] = 9000, ["auto_route"] = true,
                    ["route_exclude_address"] = KernelBypassNetworks,
                    ["strict_route"] = false, ["stack"] = "system",
                }
            },
            ["outbounds"] = new object[]
            {
                new Dictionary<string, object>
                {
                    ["type"] = "socks", ["tag"] = "proxy", ["server"] = proxyHost,
                    ["server_port"] = proxyPort, ["version"] = "5", ["network"] = "tcp",
                    ["connect_timeout"] = "10s", ["tcp_keep_alive"] = "30s",
                    ["tcp_keep_alive_interval"] = "15s",
                },
                new Dictionary<string, object> { ["type"] = "direct", ["tag"] = "direct" },
                new Dictionary<string, object> { ["type"] = "block", ["tag"] = "block" },
            },
            ["route"] = new Dictionary<string, object>
            {
                ["auto_detect_interface"] = true,
                ["rules"] = rules.ToArray(),
                ["final"] = settings.TrafficRoutingMode == TrafficRoutingModes.Whitelist ? "direct" : "proxy",
            },
        };
        return Serializer.Serialize(root);
    }

    private static void AddApplicationRules(List<object> rules, string[] names, string[] paths,
        string? network, int? port, string outbound)
    {
        if (names.Length > 0)
        {
            var fields = new Dictionary<string, object> { ["process_name"] = names };
            if (network != null) fields["network"] = network;
            if (port.HasValue) fields["port"] = port.Value;
            rules.Add(RouteRule(fields, outbound));
        }
        if (paths.Length > 0)
        {
            var fields = new Dictionary<string, object> { ["process_path"] = paths };
            if (network != null) fields["network"] = network;
            if (port.HasValue) fields["port"] = port.Value;
            rules.Add(RouteRule(fields, outbound));
        }
    }

    private static Dictionary<string, object> RouteRule(Dictionary<string, object> fields, string outbound)
    {
        fields["action"] = "route";
        fields["outbound"] = outbound;
        return fields;
    }
}

public sealed class TrafficRoutingController : IDisposable
{
    private static readonly JavaScriptSerializer Serializer = new();
    private Process? _helperProcess;
    private string? _session;
    private string? _statusPath;
    private string? _controlPath;

    public static string RoutingDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CloudflareProxy", "routing");
    public bool IsActive { get; private set; }
    public bool IsBusy { get; private set; }
    public TrafficRoutingStatus LastStatus { get; private set; } = new();

    public async Task EnableAsync(AppSettings settings, Action<int, string> progress,
        CancellationToken cancellationToken)
    {
        if (IsBusy)
            throw new InvalidOperationException("Маршрутизация уже переключается.");
        if (IsActive)
            return;
        IsBusy = true;
        try
        {
            LastStatus = new TrafficRoutingStatus { State = "starting", Message = "Подготавливаю маршрутизацию" };
            var host = settings.ListenAddress == "0.0.0.0" ? "127.0.0.1" : settings.ListenAddress;
            progress(0, "Проверяю SOCKS5 перед включением маршрутизации");
            var healthy = await Task.Run(() => SocksHealthProbe.Check(host, settings.ListenPort, 3000),
                cancellationToken).ConfigureAwait(false);
            if (!healthy)
                throw new InvalidOperationException("SOCKS5 сейчас не отвечает. Маршрутизация не включена, интернет остаётся прямым.");

            await TrafficRoutingRuntime.EnsureAsync(progress, cancellationToken).ConfigureAwait(false);
            Directory.CreateDirectory(RoutingDirectory);
            _session = Guid.NewGuid().ToString("N");
            var configPath = Path.Combine(RoutingDirectory, "routing-" + _session + ".json");
            _statusPath = Path.Combine(RoutingDirectory, "status-" + _session + ".json");
            _controlPath = Path.Combine(RoutingDirectory, "stop-" + _session + ".txt");
            File.WriteAllText(configPath, TrafficRoutingConfig.Build(settings, host, settings.ListenPort),
                new UTF8Encoding(false));
            CheckConfiguration(configPath);

            var executable = Process.GetCurrentProcess().MainModule?.FileName
                ?? throw new InvalidOperationException("Не удалось определить путь к приложению.");
            var arguments = string.Join(" ", new[]
            {
                "--routing-helper", "--engine", Quote(TrafficRoutingRuntime.EnginePath),
                "--config", Quote(configPath), "--status", Quote(_statusPath),
                "--control", Quote(_controlPath), "--parent", Process.GetCurrentProcess().Id.ToString(),
                "--session", _session, "--host", host, "--port", settings.ListenPort.ToString(),
            });
            try
            {
                _helperProcess = Process.Start(new ProcessStartInfo
                {
                    FileName = executable,
                    Arguments = arguments,
                    UseShellExecute = true,
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Hidden,
                }) ?? throw new InvalidOperationException("Не удалось запустить модуль маршрутизации.");
            }
            catch (Win32Exception exception) when (exception.NativeErrorCode == 1223)
            {
                throw new InvalidOperationException("Для TUN-режима нужно разрешить запрос контроля учётных записей Windows.");
            }

            progress(100, "Жду запуска TUN-маршрутизации");
            var deadline = DateTime.UtcNow.AddSeconds(25);
            while (DateTime.UtcNow < deadline)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var status = ReadStatus();
                if (status?.State == "running")
                {
                    LastStatus = status;
                    IsActive = true;
                    return;
                }
                if (status != null && status.State is "error" or "fail_open")
                    throw new InvalidOperationException(status.Message);
                if (_helperProcess.HasExited)
                    throw new InvalidOperationException("Модуль маршрутизации завершился до запуска.");
                await Task.Delay(250, cancellationToken).ConfigureAwait(false);
            }
            RequestStop();
            throw new InvalidOperationException("TUN-марштизация не запустилась за 25 секунд.");
        }
        catch (OperationCanceledException)
        {
            RequestStop();
            IsActive = false;
            LastStatus = new TrafficRoutingStatus { State = "stopped", Message = "Маршрутизация отменена" };
            throw;
        }
        catch (Exception exception)
        {
            RequestStop();
            IsActive = false;
            LastStatus = new TrafficRoutingStatus { State = "error", Message = exception.Message };
            throw;
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (IsBusy)
            return;
        IsBusy = true;
        try
        {
            RequestStop();
            var deadline = DateTime.UtcNow.AddSeconds(12);
            while (DateTime.UtcNow < deadline)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var status = ReadStatus();
                if (status != null && status.State is "stopped" or "fail_open" or "error")
                    break;
                if (_helperProcess == null || _helperProcess.HasExited)
                    break;
                await Task.Delay(200, cancellationToken).ConfigureAwait(false);
            }
            IsActive = false;
            LastStatus = new TrafficRoutingStatus { Session = _session ?? "", State = "stopped", Message = "Трафик идёт напрямую" };
        }
        finally
        {
            IsBusy = false;
        }
    }

    public TrafficRoutingStatus PollStatus()
    {
        var status = ReadStatus();
        if (status == null)
            return LastStatus;
        LastStatus = status;
        IsActive = status.State == "running";
        return status;
    }

    public void RequestStop()
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(_controlPath) && !string.IsNullOrWhiteSpace(_session))
                File.WriteAllText(_controlPath, _session, Encoding.ASCII);
        }
        catch { }
    }

    private TrafficRoutingStatus? ReadStatus()
    {
        if (string.IsNullOrWhiteSpace(_statusPath) || !File.Exists(_statusPath))
            return null;
        try
        {
            var status = Serializer.Deserialize<TrafficRoutingStatus>(File.ReadAllText(_statusPath));
            return status != null && status.Session == _session ? status : null;
        }
        catch { return null; }
    }

    private static void CheckConfiguration(string configPath) =>
        TrafficRoutingRuntime.VerifyProcess(TrafficRoutingRuntime.EnginePath,
            "check -c " + Quote(configPath), "Конфигурация TUN некорректна");

    internal static string Quote(string value) => "\"" + value.Replace("\"", "\\\"") + "\"";

    public void Dispose()
    {
        RequestStop();
        try { _helperProcess?.Dispose(); } catch { }
    }
}

public static class ElevatedTrafficRoutingHelper
{
    private static readonly JavaScriptSerializer Serializer = new();

    public static async Task<int> RunAsync(string[] arguments)
    {
        var options = ParseOptions(arguments);
        var session = Required(options, "session");
        var statusPath = ValidateRoutingPath(Required(options, "status"));
        var controlPath = ValidateRoutingPath(Required(options, "control"));
        var configPath = ValidateRoutingPath(Required(options, "config"));
        var engine = Path.GetFullPath(Required(options, "engine"));
        var runtimeRoot = Path.GetFullPath(RuntimeBootstrapper.RuntimeRoot).TrimEnd(Path.DirectorySeparatorChar) +
                          Path.DirectorySeparatorChar;
        if (!engine.StartsWith(runtimeRoot, StringComparison.OrdinalIgnoreCase) || !File.Exists(engine))
            throw new InvalidOperationException("Недопустимый путь к движку маршрутизации.");
        if (!int.TryParse(Required(options, "parent"), out var parentPid) || parentPid <= 0)
            throw new InvalidOperationException("Некорректный PID основного приложения.");
        if (!int.TryParse(Required(options, "port"), out var proxyPort) || proxyPort is < 1 or > 65535)
            throw new InvalidOperationException("Некорректный порт SOCKS5.");
        var proxyHost = Required(options, "host");

        using var mutex = new Mutex(true, @"Global\CloudflareProxyTrafficRouting", out var ownsMutex);
        if (!ownsMutex)
        {
            WriteStatus(statusPath, session, "error", "Маршрутизация уже запущена другим экземпляром.", 0);
            return 2;
        }

        Process? engineProcess = null;
        ProcessJob? job = null;
        var terminalState = "stopped";
        var terminalMessage = "Маршрутизация выключена, интернет работает напрямую";
        try
        {
            TryDelete(controlPath);
            WriteStatus(statusPath, session, "starting", "Запускаю защищённый TUN-маршрут", 0);
            var logPath = Path.Combine(TrafficRoutingController.RoutingDirectory, "sing-box.log");
            RotateLog(logPath);
            var startInfo = new ProcessStartInfo
            {
                FileName = engine,
                Arguments = "run -c " + TrafficRoutingController.Quote(configPath),
                WorkingDirectory = Path.GetDirectoryName(engine)!,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            engineProcess = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
            var logLock = new object();
            engineProcess.OutputDataReceived += (_, e) => AppendLog(logPath, e.Data, logLock);
            engineProcess.ErrorDataReceived += (_, e) => AppendLog(logPath, e.Data, logLock);
            if (!engineProcess.Start())
                throw new InvalidOperationException("Не удалось запустить sing-box.");
            job = new ProcessJob(engineProcess);
            engineProcess.BeginOutputReadLine();
            engineProcess.BeginErrorReadLine();

            await Task.Delay(1500).ConfigureAwait(false);
            if (engineProcess.HasExited)
                throw new InvalidOperationException("TUN-движок завершился с кодом " + engineProcess.ExitCode + ".");
            WriteStatus(statusPath, session, "running", "Трафик выбранных приложений идёт через прокси", engineProcess.Id);

            var healthFailures = 0;
            while (true)
            {
                if (!IsProcessAlive(parentPid) || StopRequested(controlPath, session))
                    break;
                if (engineProcess.HasExited)
                    throw new InvalidOperationException("TUN-движок неожиданно остановился.");
                var healthy = SocksHealthProbe.Check(proxyHost, proxyPort, 1800);
                healthFailures = healthy ? 0 : healthFailures + 1;
                if (healthFailures >= 3)
                {
                    terminalState = "fail_open";
                    terminalMessage = "Прокси недоступен — TUN отключён, интернет автоматически возвращён напрямую";
                    break;
                }
                await Task.Delay(1200).ConfigureAwait(false);
            }
            return 0;
        }
        catch (Exception exception)
        {
            terminalState = "error";
            terminalMessage = "Маршрутизация отключена: " + exception.Message;
            return 1;
        }
        finally
        {
            try
            {
                if (engineProcess is { HasExited: false })
                {
                    engineProcess.Kill();
                    engineProcess.WaitForExit(5000);
                }
            }
            catch { }
            job?.Dispose();
            engineProcess?.Dispose();
            WriteStatus(statusPath, session, terminalState, terminalMessage, 0);
            TryDelete(controlPath);
        }
    }

    private static Dictionary<string, string> ParseOptions(string[] args)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index + 1 < args.Length; index += 2)
        {
            if (!args[index].StartsWith("--", StringComparison.Ordinal))
                continue;
            result[args[index].Substring(2)] = args[index + 1];
        }
        return result;
    }

    private static string Required(Dictionary<string, string> options, string name) =>
        options.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidOperationException("Отсутствует параметр маршрутизации: " + name);

    private static string ValidateRoutingPath(string path)
    {
        var root = Path.GetFullPath(TrafficRoutingController.RoutingDirectory).TrimEnd(Path.DirectorySeparatorChar) +
                   Path.DirectorySeparatorChar;
        var full = Path.GetFullPath(path);
        if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Недопустимый служебный путь маршрутизации.");
        return full;
    }

    private static void WriteStatus(string path, string session, string state, string message, int enginePid)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var temporary = path + ".tmp";
            File.WriteAllText(temporary, Serializer.Serialize(new TrafficRoutingStatus
            {
                Session = session, State = state, Message = message, EnginePid = enginePid,
            }), new UTF8Encoding(false));
            if (File.Exists(path)) File.Replace(temporary, path, null); else File.Move(temporary, path);
        }
        catch { }
    }

    private static bool StopRequested(string path, string session)
    {
        try { return File.Exists(path) && File.ReadAllText(path).Trim() == session; }
        catch { return false; }
    }

    private static bool IsProcessAlive(int processId)
    {
        try { using var process = Process.GetProcessById(processId); return !process.HasExited; }
        catch { return false; }
    }

    private static void AppendLog(string path, string? line, object sync)
    {
        if (string.IsNullOrWhiteSpace(line)) return;
        try { lock (sync) File.AppendAllText(path, DateTime.Now.ToString("O") + " " + line + Environment.NewLine); }
        catch { }
    }

    private static void RotateLog(string path)
    {
        const int retainedBytes = 2 * 1024 * 1024;
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length <= retainedBytes)
                return;
            var backup = path + ".1";
            var temporary = backup + ".tmp";
            using (var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (var output = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                input.Position = Math.Max(0, input.Length - retainedBytes);
                input.CopyTo(output);
            }
            TryDelete(backup);
            File.Move(temporary, backup);
            File.Delete(path);
        }
        catch { }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}

internal static class SocksHealthProbe
{
    private static readonly (string Host, int Port)[] Targets =
    {
        ("1.1.1.1", 443),
        ("github.com", 443),
    };

    public static bool Check(string host, int port, int timeoutMilliseconds)
    {
        if (host == "0.0.0.0") host = "127.0.0.1";
        var localTimeout = Math.Min(400, Math.Max(200, timeoutMilliseconds / 4));
        if (!CanConnect(host, port, localTimeout))
            return false;
        var attemptTimeout = Math.Max(500, (timeoutMilliseconds - localTimeout) / Targets.Length);
        return Targets.Any(target => CheckTarget(host, port, target.Host, target.Port, attemptTimeout));
    }

    private static bool CanConnect(string host, int port, int timeoutMilliseconds)
    {
        try
        {
            using var client = new TcpClient();
            var connect = client.BeginConnect(host, port, null, null);
            try
            {
                if (!connect.AsyncWaitHandle.WaitOne(timeoutMilliseconds))
                    return false;
                client.EndConnect(connect);
                return true;
            }
            finally
            {
                connect.AsyncWaitHandle.Close();
            }
        }
        catch
        {
            return false;
        }
    }

    private static bool CheckTarget(string proxyHost, int proxyPort, string targetHost, int targetPort,
        int timeoutMilliseconds)
    {
        try
        {
            using var client = new TcpClient { ReceiveTimeout = timeoutMilliseconds, SendTimeout = timeoutMilliseconds };
            var connect = client.BeginConnect(proxyHost, proxyPort, null, null);
            try
            {
                if (!connect.AsyncWaitHandle.WaitOne(timeoutMilliseconds)) return false;
                client.EndConnect(connect);
            }
            finally { connect.AsyncWaitHandle.Close(); }

            using var stream = client.GetStream();
            stream.Write(new byte[] { 5, 1, 0 }, 0, 3);
            var greeting = ReadExact(stream, 2);
            if (greeting[0] != 5 || greeting[1] != 0) return false;
            var request = BuildConnectRequest(targetHost, targetPort);
            stream.Write(request, 0, request.Length);
            var response = ReadExact(stream, 4);
            return response[0] == 5 && response[1] == 0;
        }
        catch { return false; }
    }

    private static byte[] BuildConnectRequest(string targetHost, int targetPort)
    {
        byte addressType;
        byte[] address;
        if (IPAddress.TryParse(targetHost, out var ipAddress))
        {
            addressType = ipAddress.AddressFamily == AddressFamily.InterNetwork ? (byte)1 : (byte)4;
            address = ipAddress.GetAddressBytes();
        }
        else
        {
            var domain = Encoding.ASCII.GetBytes(targetHost);
            if (domain.Length is 0 or > 255)
                throw new InvalidOperationException("Некорректная цель проверки SOCKS5.");
            addressType = 3;
            address = new[] { (byte)domain.Length }.Concat(domain).ToArray();
        }

        var request = new byte[4 + address.Length + 2];
        request[0] = 5;
        request[1] = 1;
        request[2] = 0;
        request[3] = addressType;
        Buffer.BlockCopy(address, 0, request, 4, address.Length);
        request[request.Length - 2] = (byte)(targetPort >> 8);
        request[request.Length - 1] = (byte)targetPort;
        return request;
    }

    private static byte[] ReadExact(Stream stream, int count)
    {
        var buffer = new byte[count];
        var offset = 0;
        while (offset < count)
        {
            var read = stream.Read(buffer, offset, count - offset);
            if (read <= 0) throw new EndOfStreamException();
            offset += read;
        }
        return buffer;
    }
}

internal sealed class ProcessJob : IDisposable
{
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private readonly IntPtr _handle;

    public ProcessJob(Process process)
    {
        _handle = CreateJobObject(IntPtr.Zero, null);
        if (_handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        var information = new JobObjectExtendedLimitInformation();
        information.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
        var length = Marshal.SizeOf(information);
        if (!SetInformationJobObject(_handle, 9, ref information, (uint)length) ||
            !AssignProcessToJobObject(_handle, process.Handle))
        {
            var error = Marshal.GetLastWin32Error();
            CloseHandle(_handle);
            throw new Win32Exception(error);
        }
    }

    public void Dispose() { if (_handle != IntPtr.Zero) CloseHandle(_handle); }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr securityAttributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr job, int informationClass,
        ref JobObjectExtendedLimitInformation information, uint length);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}

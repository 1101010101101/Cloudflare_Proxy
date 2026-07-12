using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CloudflareProxyApp;

public static class RuntimeBootstrapper
{
    private const string PythonVersion = "3.13.14";
    private const string PythonUrl = "https://www.python.org/ftp/python/3.13.14/python-3.13.14-embed-amd64.zip";
    private const string PythonSha256 = "90B4E5B9898B72D744650524BFF92377C367F44BD5FBD09E3148656C080AD907";
    private const string OpenSshUrl = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.0.0.0p2-Preview/OpenSSH-Win64.zip";
    private const string OpenSshSha256 = "23F50F3458C4C5D0B12217C6A5DDFDE0137210A30FA870E98B29827F7B43ABA5";
    private const string RuntimeMarker = "runtime-ready-v2";
    private static readonly SemaphoreSlim InstallLock = new SemaphoreSlim(1, 1);

    public static string RuntimeRoot
    {
        get
        {
            var configured = Environment.GetEnvironmentVariable("CLOUDFLARE_PROXY_RUNTIME_DIR");
            return string.IsNullOrWhiteSpace(configured)
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "CloudflareProxy", "runtime")
                : Path.GetFullPath(configured);
        }
    }

    public static string PythonDirectory => Path.Combine(RuntimeRoot, "python-" + PythonVersion + "-x64");
    public static string PythonPath => Path.Combine(PythonDirectory, "python.exe");
    public static string BackendPath => Path.Combine(RuntimeRoot, "cloudflare_proxy_setup.py");
    public static string PortableSshDirectory => Path.Combine(RuntimeRoot, "openssh-win64");
    private static string MarkerPath => Path.Combine(PythonDirectory, RuntimeMarker);

    public static bool IsReady => File.Exists(PythonPath) && File.Exists(MarkerPath) && File.Exists(BackendPath);

    public static async Task EnsureAsync(Action<int, string> progress, CancellationToken cancellationToken)
    {
        await InstallLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(RuntimeRoot);
            WriteEmbeddedResource("CloudflareProxy.backend.py", BackendPath);

            if (!IsReady)
                await InstallPythonAsync(progress, cancellationToken).ConfigureAwait(false);
            else
                progress(12, "Переносимый Python уже установлен");

            var forcePortableSsh = Environment.GetEnvironmentVariable("CLOUDFLARE_PROXY_FORCE_PORTABLE_SSH") == "1";
            if (forcePortableSsh || FindExecutable("ssh.exe") == null)
                await InstallOpenSshAsync(progress, cancellationToken).ConfigureAwait(false);
            else
                progress(15, "OpenSSH готов");
        }
        finally
        {
            InstallLock.Release();
        }
    }

    public static string BuildPathEnvironment()
    {
        var current = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        return File.Exists(Path.Combine(PortableSshDirectory, "ssh.exe"))
            ? PortableSshDirectory + ";" + current
            : current;
    }

    private static async Task InstallPythonAsync(Action<int, string> progress, CancellationToken cancellationToken)
    {
        progress(2, "Скачиваю переносимый Python " + PythonVersion);
        var archivePath = Path.Combine(RuntimeRoot, "python-download.tmp");
        var workDirectory = Path.Combine(RuntimeRoot, "python-installing");
        DeleteDirectorySafe(workDirectory);
        Directory.CreateDirectory(workDirectory);

        try
        {
            await DownloadAsync(PythonUrl, archivePath, 2, 8, progress, cancellationToken).ConfigureAwait(false);
            progress(8, "Проверяю цифровой отпечаток Python");
            VerifySha256(archivePath, PythonSha256, "Python");
            cancellationToken.ThrowIfCancellationRequested();

            var extracted = Path.Combine(workDirectory, "python");
            Directory.CreateDirectory(extracted);
            ZipFile.ExtractToDirectory(archivePath, extracted);
            ConfigurePythonPath(extracted);

            var sitePackages = Path.Combine(extracted, "Lib", "site-packages");
            Directory.CreateDirectory(sitePackages);
            ExtractEmbeddedZip("CloudflareProxy.python-vendor.zip", sitePackages);

            progress(10, "Проверяю Python и сетевые библиотеки");
            TestProcess(Path.Combine(extracted, "python.exe"),
                "-c \"import requests, ssl; print(requests.__version__)\"", 20000,
                "Проверка переносимого Python завершилась ошибкой");

            DeleteDirectorySafe(PythonDirectory);
            Directory.Move(extracted, PythonDirectory);
            File.WriteAllText(MarkerPath, PythonVersion, Encoding.ASCII);
            progress(12, "Переносимый Python установлен");
        }
        finally
        {
            TryDeleteFile(archivePath);
            DeleteDirectorySafe(workDirectory);
        }
    }

    private static async Task InstallOpenSshAsync(Action<int, string> progress, CancellationToken cancellationToken)
    {
        progress(12, "Скачиваю portable OpenSSH");
        var archivePath = Path.Combine(RuntimeRoot, "openssh-download.tmp");
        var workDirectory = Path.Combine(RuntimeRoot, "openssh-installing");
        DeleteDirectorySafe(workDirectory);
        Directory.CreateDirectory(workDirectory);
        try
        {
            await DownloadAsync(OpenSshUrl, archivePath, 12, 14, progress, cancellationToken).ConfigureAwait(false);
            VerifySha256(archivePath, OpenSshSha256, "OpenSSH");
            ZipFile.ExtractToDirectory(archivePath, workDirectory);
            var ssh = Directory.GetFiles(workDirectory, "ssh.exe", SearchOption.AllDirectories).FirstOrDefault();
            if (ssh == null)
                throw new InvalidOperationException("В архиве OpenSSH отсутствует ssh.exe.");
            var source = Path.GetDirectoryName(ssh)!;
            TestProcess(ssh, "-V", 10000, "Проверка portable OpenSSH завершилась ошибкой");
            DeleteDirectorySafe(PortableSshDirectory);
            Directory.Move(source, PortableSshDirectory);
            progress(15, "Portable OpenSSH установлен");
        }
        finally
        {
            TryDeleteFile(archivePath);
            DeleteDirectorySafe(workDirectory);
        }
    }

    private static async Task DownloadAsync(string url, string destination, int fromProgress, int toProgress,
        Action<int, string> progress, CancellationToken cancellationToken)
    {
        ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
        using var client = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("CloudflareProxy/2.2");
        using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var total = response.Content.Headers.ContentLength;
        using var input = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
        using var output = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None, 81920, true);
        var buffer = new byte[81920];
        long received = 0;
        var lastReportedProgress = -1;
        int read;
        while ((read = await input.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false)) > 0)
        {
            await output.WriteAsync(buffer, 0, read, cancellationToken).ConfigureAwait(false);
            received += read;
            if (total.HasValue && total.Value > 0)
            {
                var percent = fromProgress + (int)((toProgress - fromProgress) * received / total.Value);
                percent = Math.Min(toProgress, percent);
                if (percent != lastReportedProgress)
                {
                    lastReportedProgress = percent;
                    progress(percent, "Загружено " + (received / 1024 / 1024) + " МБ");
                }
            }
        }
    }

    private static void ConfigurePythonPath(string directory)
    {
        var pathFile = Directory.GetFiles(directory, "python*._pth", SearchOption.TopDirectoryOnly).FirstOrDefault();
        if (pathFile == null)
            throw new InvalidOperationException("В portable Python отсутствует файл ._pth.");
        var lines = File.ReadAllLines(pathFile).ToList();
        for (var index = 0; index < lines.Count; index++)
            if (lines[index].Trim().Equals("#import site", StringComparison.OrdinalIgnoreCase))
                lines[index] = "import site";
        if (!lines.Any(line => line.Trim().Equals("Lib\\site-packages", StringComparison.OrdinalIgnoreCase)))
            lines.Insert(Math.Max(0, lines.Count - 1), "Lib\\site-packages");
        File.WriteAllLines(pathFile, lines, new UTF8Encoding(false));
    }

    private static void WriteEmbeddedResource(string name, string destination)
    {
        var bytes = ReadEmbeddedResource(name);
        if (File.Exists(destination) && File.ReadAllBytes(destination).SequenceEqual(bytes))
            return;
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        var temporary = destination + ".tmp";
        File.WriteAllBytes(temporary, bytes);
        if (File.Exists(destination))
            File.Replace(temporary, destination, null);
        else
            File.Move(temporary, destination);
    }

    private static byte[] ReadEmbeddedResource(string name)
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name)
            ?? throw new InvalidOperationException("В EXE отсутствует ресурс " + name + ".");
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return memory.ToArray();
    }

    private static void ExtractEmbeddedZip(string name, string destination)
    {
        using var stream = new MemoryStream(ReadEmbeddedResource(name));
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read);
        foreach (var entry in archive.Entries)
        {
            var path = Path.GetFullPath(Path.Combine(destination, entry.FullName.Replace('/', Path.DirectorySeparatorChar)));
            var root = Path.GetFullPath(destination).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Небезопасный путь внутри встроенного архива.");
            if (string.IsNullOrEmpty(entry.Name))
            {
                Directory.CreateDirectory(path);
                continue;
            }
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            entry.ExtractToFile(path, true);
        }
    }

    private static void VerifySha256(string path, string expected, string component)
    {
        using var algorithm = SHA256.Create();
        using var stream = File.OpenRead(path);
        var actual = BitConverter.ToString(algorithm.ComputeHash(stream)).Replace("-", "");
        if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(component + " не прошёл проверку SHA-256. Файл удалён.");
    }

    private static void TestProcess(string executable, string arguments, int timeout, string errorPrefix)
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
        if (!process.WaitForExit(timeout))
        {
            try { process.Kill(); } catch { }
            throw new TimeoutException(errorPrefix + ": превышено время ожидания.");
        }
        if (process.ExitCode != 0)
            throw new InvalidOperationException(errorPrefix + ": " + (string.IsNullOrWhiteSpace(error) ? output : error).Trim());
    }

    private static string? FindExecutable(string executable)
    {
        var system = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "OpenSSH", executable);
        if (File.Exists(system))
            return system;
        var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        return path.Split(Path.PathSeparator).Select(part => Path.Combine(part.Trim('"'), executable)).FirstOrDefault(File.Exists);
    }

    private static void DeleteDirectorySafe(string path)
    {
        try
        {
            var root = Path.GetFullPath(RuntimeRoot).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            var target = Path.GetFullPath(path);
            if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase) || target.Equals(root, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Отказано в удалении пути вне runtime-каталога.");
            if (Directory.Exists(target))
                Directory.Delete(target, true);
        }
        catch (DirectoryNotFoundException)
        {
        }
    }

    private static void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}

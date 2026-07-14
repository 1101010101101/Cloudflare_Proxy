using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.Web.Script.Serialization;
using Microsoft.Win32;

namespace CloudflareProxyApp;

public sealed class AppSettings
{
    public bool StartWithWindows { get; set; }
    public bool StartInTray { get; set; } = true;
    public bool ConnectOnStartup { get; set; }
    public bool ShowTrayNotifications { get; set; } = true;
    public bool CheckExitInfo { get; set; } = true;
    public string ListenAddress { get; set; } = "127.0.0.1";
    public int ListenPort { get; set; } = 1081;
    public bool EnableTrafficRoutingOnConnect { get; set; }
    public string TrafficRoutingMode { get; set; } = TrafficRoutingModes.Whitelist;
    public string TrafficProxyApplications { get; set; } = "";
    public string TrafficDirectApplications { get; set; } = "";
    // Kept only to migrate settings written by the first routing beta.
    public string TrafficApplications { get; set; } = "";

    public AppSettings Copy() => new()
    {
        StartWithWindows = StartWithWindows,
        StartInTray = StartInTray,
        ConnectOnStartup = ConnectOnStartup,
        ShowTrayNotifications = ShowTrayNotifications,
        CheckExitInfo = CheckExitInfo,
        ListenAddress = ListenAddress,
        ListenPort = ListenPort,
        EnableTrafficRoutingOnConnect = EnableTrafficRoutingOnConnect,
        TrafficRoutingMode = TrafficRoutingMode,
        TrafficProxyApplications = TrafficProxyApplications,
        TrafficDirectApplications = TrafficDirectApplications,
        TrafficApplications = "",
    };
}

public static class SettingsService
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunValueName = "CloudflareProxy";
    private static readonly JavaScriptSerializer Serializer = new JavaScriptSerializer();

    public static string SettingsPath
    {
        get
        {
            var configured = Environment.GetEnvironmentVariable("CLOUDFLARE_PROXY_SETTINGS_PATH");
            return string.IsNullOrWhiteSpace(configured)
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "cloudflare_proxy", "ui-settings.json")
                : Path.GetFullPath(configured);
        }
    }

    public static AppSettings Load()
    {
        try
        {
            if (!File.Exists(SettingsPath))
                return new AppSettings();
            var settings = Serializer.Deserialize<AppSettings>(File.ReadAllText(SettingsPath))
                ?? new AppSettings();
            Validate(settings);
            return settings;
        }
        catch
        {
            return new AppSettings();
        }
    }

    public static void Save(AppSettings settings)
    {
        Validate(settings);
        if (Environment.GetEnvironmentVariable("CLOUDFLARE_PROXY_DISABLE_AUTOSTART_WRITE") != "1")
            ApplyWindowsStartup(settings.StartWithWindows);

        var directory = Path.GetDirectoryName(SettingsPath)!;
        Directory.CreateDirectory(directory);
        var temporary = SettingsPath + ".tmp";
        File.WriteAllText(temporary, Serializer.Serialize(settings));
        if (File.Exists(SettingsPath))
            File.Replace(temporary, SettingsPath, null);
        else
            File.Move(temporary, SettingsPath);
    }

    public static void Validate(AppSettings settings)
    {
        if (!IPAddress.TryParse(settings.ListenAddress, out var address) ||
            address.AddressFamily != AddressFamily.InterNetwork)
            throw new InvalidOperationException("Укажите корректный IPv4-адрес.");
        var firstByte = address.GetAddressBytes()[0];
        if (firstByte is >= 224 and <= 239 || address.Equals(IPAddress.Broadcast))
            throw new InvalidOperationException("Этот IPv4-адрес нельзя использовать для SOCKS5.");
        if (settings.ListenPort is < 1 or > 65535)
            throw new InvalidOperationException("Порт должен быть от 1 до 65535.");
        if (settings.TrafficRoutingMode is not (TrafficRoutingModes.Whitelist or TrafficRoutingModes.Blacklist))
            throw new InvalidOperationException("Неизвестный режим списка приложений.");
        if (!string.IsNullOrWhiteSpace(settings.TrafficApplications))
        {
            if (settings.TrafficRoutingMode == TrafficRoutingModes.Blacklist &&
                string.IsNullOrWhiteSpace(settings.TrafficDirectApplications))
                settings.TrafficDirectApplications = settings.TrafficApplications;
            else if (settings.TrafficRoutingMode == TrafficRoutingModes.Whitelist &&
                     string.IsNullOrWhiteSpace(settings.TrafficProxyApplications))
                settings.TrafficProxyApplications = settings.TrafficApplications;
            settings.TrafficApplications = "";
        }
        settings.ListenAddress = address.ToString();
        settings.TrafficProxyApplications = TrafficApplicationList.Normalize(settings.TrafficProxyApplications);
        settings.TrafficDirectApplications = TrafficApplicationList.Normalize(settings.TrafficDirectApplications);
    }

    private static void ApplyWindowsStartup(bool enabled)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKeyPath, writable: true)
            ?? throw new InvalidOperationException("Не удалось открыть раздел автозагрузки Windows.");
        if (!enabled)
        {
            key.DeleteValue(RunValueName, throwOnMissingValue: false);
            return;
        }

        var executable = Process.GetCurrentProcess().MainModule?.FileName;
        if (string.IsNullOrWhiteSpace(executable))
            throw new InvalidOperationException("Не удалось определить путь к приложению для автозагрузки.");
        key.SetValue(RunValueName, $"\"{executable}\" --autostart", RegistryValueKind.String);
    }

    public static bool IsAutostartLaunch() => Environment.GetCommandLineArgs()
        .Any(argument => string.Equals(argument, "--autostart", StringComparison.OrdinalIgnoreCase));
}

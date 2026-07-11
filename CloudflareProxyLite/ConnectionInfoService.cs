using System.Diagnostics;
using System.Text;

namespace CloudflareProxyApp;

public sealed record ExitConnectionInfo(string IpAddress, string CountryCode, string CountryName, long LatencyMs);

public static class ConnectionInfoService
{
    private static readonly IReadOnlyDictionary<string, string> CountryNames =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["AT"] = "Австрия", ["AU"] = "Австралия", ["BE"] = "Бельгия",
            ["BG"] = "Болгария", ["BR"] = "Бразилия", ["CA"] = "Канада",
            ["CH"] = "Швейцария", ["CZ"] = "Чехия", ["DE"] = "Германия",
            ["DK"] = "Дания", ["EE"] = "Эстония", ["ES"] = "Испания",
            ["FI"] = "Финляндия", ["FR"] = "Франция", ["GB"] = "Великобритания",
            ["GR"] = "Греция", ["HR"] = "Хорватия", ["HU"] = "Венгрия",
            ["IE"] = "Ирландия", ["IN"] = "Индия", ["IS"] = "Исландия",
            ["IT"] = "Италия", ["JP"] = "Япония", ["KR"] = "Южная Корея",
            ["LT"] = "Литва", ["LU"] = "Люксембург", ["LV"] = "Латвия",
            ["NL"] = "Нидерланды", ["NO"] = "Норвегия", ["PL"] = "Польша",
            ["PT"] = "Португалия", ["RO"] = "Румыния", ["RU"] = "Россия",
            ["SE"] = "Швеция", ["SG"] = "Сингапур", ["SI"] = "Словения",
            ["SK"] = "Словакия", ["TR"] = "Турция", ["UA"] = "Украина",
            ["US"] = "США",
        };

    public static Task<ExitConnectionInfo> QueryAsync(string endpoint, CancellationToken cancellationToken)
    {
        return Task.Run(() => Query(endpoint, cancellationToken), cancellationToken);
    }

    private static ExitConnectionInfo Query(string endpoint, CancellationToken cancellationToken)
    {
        var address = endpoint.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()
            ?? "127.0.0.1:1081";
        if (address.StartsWith("0.0.0.0:", StringComparison.Ordinal))
            address = "127.0.0.1:" + address.Substring("0.0.0.0:".Length);

        var startInfo = new ProcessStartInfo
        {
            FileName = "curl.exe",
            Arguments = "--silent --show-error --fail --socks5-hostname " + address +
                        " --max-time 12 https://www.cloudflare.com/cdn-cgi/trace",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        var stopwatch = Stopwatch.StartNew();
        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Не удалось запустить curl.exe.");
        using var registration = cancellationToken.Register(() =>
        {
            try { if (!process.HasExited) process.Kill(); } catch { }
        });
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        if (!process.WaitForExit(15000))
        {
            try { process.Kill(); } catch { }
            throw new TimeoutException("Проверка внешнего IP превысила 15 секунд.");
        }
        cancellationToken.ThrowIfCancellationRequested();
        if (process.ExitCode != 0)
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(error) ? "curl завершился с ошибкой." : error.Trim());
        stopwatch.Stop();

        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = line.IndexOf('=');
            if (separator > 0)
                values[line.Substring(0, separator).Trim()] = line.Substring(separator + 1).Trim();
        }
        var ip = values.TryGetValue("ip", out var ipValue) && ipValue.Length <= 64 ? ipValue : "не определён";
        var code = values.TryGetValue("loc", out var loc) ? loc.ToUpperInvariant() : "--";
        if (code.Length != 2 || code.Any(character => !((character >= 'A' && character <= 'Z') ||
                                                        (character >= 'a' && character <= 'z'))))
            code = "--";
        var country = CountryNames.TryGetValue(code, out var name) ? name : (code == "--" ? "не определена" : code);
        return new ExitConnectionInfo(ip, code, country, Math.Max(1, stopwatch.ElapsedMilliseconds));
    }
}

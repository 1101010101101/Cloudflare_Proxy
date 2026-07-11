using System.IO;
using System.Text;
using System.Windows;

namespace CloudflareProxyApp;

public partial class App : System.Windows.Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        if (!e.Args.Any(argument => string.Equals(argument, "--bootstrap-only", StringComparison.OrdinalIgnoreCase)))
        {
            base.OnStartup(e);
            return;
        }

        ShutdownMode = ShutdownMode.OnExplicitShutdown;
        var output = Environment.GetEnvironmentVariable("CLOUDFLARE_PROXY_BOOTSTRAP_RESULT");
        var log = new StringBuilder();
        try
        {
            await RuntimeBootstrapper.EnsureAsync(
                (progress, message) => log.AppendLine(progress + "% " + message),
                CancellationToken.None);
            log.AppendLine("READY");
            if (!string.IsNullOrWhiteSpace(output))
                File.WriteAllText(output, log.ToString(), Encoding.UTF8);
            Shutdown(0);
        }
        catch (Exception exception)
        {
            log.AppendLine("ERROR: " + exception);
            if (!string.IsNullOrWhiteSpace(output))
                File.WriteAllText(output, log.ToString(), Encoding.UTF8);
            Shutdown(1);
        }
    }
}

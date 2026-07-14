using System.IO;
using System.Text;
using System.Windows;

namespace CloudflareProxyApp;

public partial class App : System.Windows.Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        if (e.Args.Length > 0 && string.Equals(e.Args[0], "--routing-helper", StringComparison.OrdinalIgnoreCase))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            try
            {
                var exitCode = await ElevatedTrafficRoutingHelper.RunAsync(e.Args.Skip(1).ToArray());
                Shutdown(exitCode);
            }
            catch
            {
                Shutdown(1);
            }
            return;
        }

        if (e.Args.Any(argument => string.Equals(argument, "--routing-bootstrap-only", StringComparison.OrdinalIgnoreCase)))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            var routingOutput = Environment.GetEnvironmentVariable("CLOUDFLARE_PROXY_ROUTING_BOOTSTRAP_RESULT");
            var routingLog = new StringBuilder();
            try
            {
                await TrafficRoutingRuntime.EnsureAsync(
                    (progress, message) => routingLog.AppendLine(progress + "% " + message), CancellationToken.None);
                routingLog.AppendLine("READY");
                if (!string.IsNullOrWhiteSpace(routingOutput))
                    File.WriteAllText(routingOutput, routingLog.ToString(), Encoding.UTF8);
                Shutdown(0);
            }
            catch (Exception exception)
            {
                routingLog.AppendLine("ERROR: " + exception);
                if (!string.IsNullOrWhiteSpace(routingOutput))
                    File.WriteAllText(routingOutput, routingLog.ToString(), Encoding.UTF8);
                Shutdown(1);
            }
            return;
        }

        if (!e.Args.Any(argument => string.Equals(argument, "--bootstrap-only", StringComparison.OrdinalIgnoreCase)))
        {
            base.OnStartup(e);
            new MainWindow().Show();
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

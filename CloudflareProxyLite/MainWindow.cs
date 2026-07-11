using System.ComponentModel;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Threading;
using Drawing = System.Drawing;
using Forms = System.Windows.Forms;
using MediaColor = System.Windows.Media.Color;
using WpfClipboard = System.Windows.Clipboard;

namespace CloudflareProxyApp;

public partial class MainWindow : Window
{
    private sealed record FlagDefinition(string First, string Second, string Third, bool Vertical = false,
        double FirstWeight = 1, double SecondWeight = 1, double ThirdWeight = 1);

    private static readonly SolidColorBrush MutedBrush = new(MediaColor.FromRgb(148, 167, 181));
    private static readonly SolidColorBrush ActiveBrush = new(MediaColor.FromRgb(21, 159, 214));
    private static readonly SolidColorBrush SuccessBrush = new(MediaColor.FromRgb(30, 186, 145));
    private static readonly SolidColorBrush ErrorBrush = new(MediaColor.FromRgb(220, 75, 91));

    private static readonly IReadOnlyDictionary<string, FlagDefinition> Flags =
        new Dictionary<string, FlagDefinition>(StringComparer.OrdinalIgnoreCase)
        {
            ["AT"] = new("#ED2939", "#FFFFFF", "#ED2939"),
            ["BE"] = new("#111111", "#FFD90C", "#EF3340", true),
            ["BG"] = new("#FFFFFF", "#00966E", "#D62612"),
            ["DE"] = new("#111111", "#DD0000", "#FFCE00"),
            ["EE"] = new("#4891D9", "#111111", "#FFFFFF"),
            ["FR"] = new("#0055A4", "#FFFFFF", "#EF4135", true),
            ["HU"] = new("#CE2939", "#FFFFFF", "#477050"),
            ["IE"] = new("#169B62", "#FFFFFF", "#FF883E", true),
            ["IT"] = new("#009246", "#FFFFFF", "#CE2B37", true),
            ["LT"] = new("#FDB913", "#006A44", "#C1272D"),
            ["LU"] = new("#EF3340", "#FFFFFF", "#00A3E0"),
            ["LV"] = new("#9E3039", "#FFFFFF", "#9E3039", false, 2, 0.65, 2),
            ["NL"] = new("#AE1C28", "#FFFFFF", "#21468B"),
            ["PL"] = new("#FFFFFF", "#DC143C", "#DC143C", false, 1, 0.5, 0.5),
            ["RO"] = new("#002B7F", "#FCD116", "#CE1126", true),
            ["RU"] = new("#FFFFFF", "#1C57A7", "#D52B1E"),
            ["UA"] = new("#0057B7", "#FFD700", "#FFD700", false, 1, 0.5, 0.5),
        };

    private readonly ProxyController _controller = new();
    private readonly CancellationTokenSource _shutdown = new();
    private readonly Forms.NotifyIcon _trayIcon;
    private readonly Forms.ToolStripMenuItem _trayToggleItem;
    private readonly DispatcherTimer _sessionTimer;
    private CancellationTokenSource? _connectionInfoCancellation;
    private AppSettings _settings = SettingsService.Load();
    private bool _proxyRunning;
    private bool _allowExit;
    private bool _trayHintShown;
    private DateTime _sessionStarted;

    public MainWindow()
    {
        InitializeComponent();
        _controller.ConfigureEndpoint(_settings.ListenAddress, _settings.ListenPort);

        _trayToggleItem = new Forms.ToolStripMenuItem("Подключиться");
        _trayToggleItem.Click += (_, _) => Dispatcher.BeginInvoke(async () => await ToggleProxyFromTrayAsync());
        var openItem = new Forms.ToolStripMenuItem("Открыть");
        openItem.Click += (_, _) => Dispatcher.BeginInvoke(RestoreFromTray);
        var exitItem = new Forms.ToolStripMenuItem("Выход");
        exitItem.Click += (_, _) => Dispatcher.BeginInvoke(ExitApplication);
        var trayMenu = new Forms.ContextMenuStrip();
        trayMenu.Items.Add(openItem);
        trayMenu.Items.Add(_trayToggleItem);
        trayMenu.Items.Add(new Forms.ToolStripSeparator());
        trayMenu.Items.Add(exitItem);

        _trayIcon = new Forms.NotifyIcon
        {
            Icon = LoadApplicationIcon(),
            Text = "Cloudflare Proxy",
            Visible = true,
            ContextMenuStrip = trayMenu,
        };
        _trayIcon.DoubleClick += (_, _) => Dispatcher.BeginInvoke(RestoreFromTray);

        _sessionTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _sessionTimer.Tick += (_, _) =>
        {
            var elapsed = DateTime.Now - _sessionStarted;
            SessionTimeText.Text = $"{(int)elapsed.TotalHours:00}:{elapsed.Minutes:00}:{elapsed.Seconds:00}";
        };

        Loaded += async (_, _) =>
        {
            var previewState = Environment.GetEnvironmentVariable("CLOUDFLARE_PROXY_UI_PREVIEW_STATE");
            if (string.Equals(previewState, "connected", StringComparison.OrdinalIgnoreCase))
            {
                ShowConnected("127.0.0.1:1081 socks5");
                _connectionInfoCancellation?.Cancel();
                ExitIpText.Text = "121.3.123.123";
                var previewCountry = Environment.GetEnvironmentVariable("CLOUDFLARE_PROXY_UI_PREVIEW_COUNTRY") ?? "US";
                ExitCountryText.Text = previewCountry.Equals("US", StringComparison.OrdinalIgnoreCase) ? "США" : previewCountry;
                LatencyText.Text = "пинг: 212 мс";
                SetFlagVisual(previewCountry);
                await Task.Delay(150);
                CapturePreviewIfRequested();
                return;
            }
            if (string.Equals(previewState, "stopped", StringComparison.OrdinalIgnoreCase))
            {
                ShowStopped();
                await Task.Delay(150);
                CapturePreviewIfRequested();
                return;
            }
            if (string.Equals(previewState, "settings", StringComparison.OrdinalIgnoreCase))
            {
                ShowStopped();
                PopulateEmbeddedSettings(_settings);
                MainContent.Visibility = Visibility.Collapsed;
                SettingsPage.Visibility = Visibility.Visible;
                await Task.Delay(150);
                CapturePreviewIfRequested();
                return;
            }
            if (string.Equals(previewState, "github_auth", StringComparison.OrdinalIgnoreCase))
            {
                ResetStages();
                SetBusy(true, "Введите код на открывшейся странице GitHub");
                HandleEvent(new ProxyEvent("github_auth", "action_required",
                    "Введите код на открывшейся странице GitHub", 20, null, "ABCD-1234",
                    "https://github.com/login/device"));
                await Task.Delay(150);
                CapturePreviewIfRequested();
                return;
            }
            if (_settings.StartWithWindows && _settings.StartInTray && SettingsService.IsAutostartLaunch())
                HideToTray(showHint: false);
            await RefreshStatusAsync();
            if (_settings.ConnectOnStartup && !_proxyRunning && !_controller.IsBusy)
                _ = StartProxyAsync();
            if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("CLOUDFLARE_PROXY_UI_PREVIEW")))
                await Task.Delay(1200);
            CapturePreviewIfRequested();
        };
        StateChanged += Window_StateChanged;
        Closing += Window_Closing;
        Closed += (_, _) =>
        {
            _connectionInfoCancellation?.Cancel();
            _connectionInfoCancellation?.Dispose();
            _shutdown.Cancel();
            _controller.Dispose();
            _shutdown.Dispose();
            _sessionTimer.Stop();
            _trayIcon.Visible = false;
            _trayIcon.Icon?.Dispose();
            _trayIcon.Dispose();
            trayMenu.Dispose();
        };
    }

    private static Drawing.Icon LoadApplicationIcon()
    {
        var resource = System.Windows.Application.GetResourceStream(
            new Uri("pack://application:,,,/Assets/cloudflare-proxy.ico"));
        if (resource?.Stream is null)
            return (Drawing.Icon)Drawing.SystemIcons.Application.Clone();
        using (resource.Stream)
        using (var icon = new Drawing.Icon(resource.Stream))
            return (Drawing.Icon)icon.Clone();
    }

    private async Task RefreshStatusAsync()
    {
        SetBusy(true, "Проверяю состояние…");
        try
        {
            await _controller.RunAsync("--status --json-events", HandleEvent, AppendLog, _shutdown.Token);
        }
        catch (Exception exception)
        {
            ShowError(exception.Message);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void Start_Click(object sender, RoutedEventArgs e) => await StartProxyAsync();

    private async Task StartProxyAsync()
    {
        ResetStages();
        EndpointCard.Visibility = Visibility.Collapsed;
        SetBusy(true, "Запускаю прокси…");
        StatusTitle.Text = "Подключение";
        LogText.Clear();

        try
        {
            var exitCode = await _controller.RunAsync("--json-events", HandleEvent, AppendLog, _shutdown.Token);
            if (exitCode != 0 && !_proxyRunning)
                ShowError("Backend завершился с ошибкой. Откройте технические детали.");
        }
        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            ShowError(exception.Message);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void Stop_Click(object sender, RoutedEventArgs e) => await StopProxyAsync();

    private async Task StopProxyAsync()
    {
        _connectionInfoCancellation?.Cancel();
        SetBusy(true, "Закрываю локальный туннель…");
        StatusTitle.Text = "Отключение";
        try
        {
            var exitCode = await _controller.RunAsync("--stop --json-events", HandleEvent, AppendLog, _shutdown.Token);
            if (exitCode != 0)
                ShowError("Не удалось полностью остановить прокси.");
        }
        catch (Exception exception)
        {
            ShowError(exception.Message);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void HandleEvent(ProxyEvent proxyEvent)
    {
        Dispatcher.Invoke(() =>
        {
            StatusMessage.Text = proxyEvent.Message;
            if (proxyEvent.Progress is { } progress)
            {
                ProgressValue.Value = progress;
                UpdateStages(progress);
            }

            if (proxyEvent.Stage == "github_auth" && !string.IsNullOrWhiteSpace(proxyEvent.AuthCode))
            {
                StatusTitle.Text = "Подтвердите вход в GitHub";
                GithubAuthCodeText.Text = proxyEvent.AuthCode;
                CopyGithubCodeButton.Content = "Скопировать код";
                GithubAuthPanel.Visibility = Visibility.Visible;
                StageRow.Height = new GridLength(136);
            }
            else if (proxyEvent.Stage != "github")
            {
                GithubAuthPanel.Visibility = Visibility.Collapsed;
                StageRow.Height = new GridLength(72);
            }

            if (proxyEvent.Status == "error")
            {
                ShowError(proxyEvent.Message);
                return;
            }

            if (proxyEvent.Stage == "ready")
                ShowConnected(proxyEvent.Endpoint ?? "127.0.0.1:1081 socks5");
            else if (proxyEvent.Stage is "idle" or "stopped")
                ShowStopped();
        });
    }

    private void ShowConnected(string endpoint)
    {
        var wasRunning = _proxyRunning;
        _proxyRunning = true;
        StatusTitle.Text = "Прокси работает";
        StatusMessage.Visibility = Visibility.Collapsed;
        ConnectedFactsPanel.Visibility = Visibility.Visible;
        FlagPlate.Visibility = Visibility.Visible;
        OfflineArtwork.Visibility = Visibility.Collapsed;
        BusyArtwork.Visibility = Visibility.Collapsed;
        EndpointText.Text = endpoint;
        EndpointCard.Visibility = Visibility.Visible;
        StagePanel.Visibility = Visibility.Collapsed;
        StartButton.Visibility = Visibility.Collapsed;
        StopButton.Visibility = Visibility.Visible;
        _trayToggleItem.Text = "Отключиться";
        _trayIcon.Text = "Cloudflare Proxy — подключён";
        if (!_sessionTimer.IsEnabled)
        {
            _sessionStarted = DateTime.Now;
            _sessionTimer.Start();
        }
        if (!wasRunning && _settings.CheckExitInfo)
            _ = RefreshExitInfoAsync(endpoint);
        else if (!_settings.CheckExitInfo)
        {
            _connectionInfoCancellation?.Cancel();
            ExitIpText.Text = "отключено";
            ExitCountryText.Text = "отключено";
            LatencyText.Text = "пинг: —";
            SetFlagVisual("--");
        }
    }

    private void ShowStopped()
    {
        _connectionInfoCancellation?.Cancel();
        _proxyRunning = false;
        StatusTitle.Text = "Прокси выключен";
        StatusMessage.Text = "Локальный SOCKS5 сейчас не принимает соединения";
        StatusMessage.Visibility = Visibility.Visible;
        ConnectedFactsPanel.Visibility = Visibility.Collapsed;
        FlagPlate.Visibility = Visibility.Collapsed;
        OfflineArtwork.Visibility = Visibility.Visible;
        BusyArtwork.Visibility = Visibility.Collapsed;
        EndpointCard.Visibility = Visibility.Collapsed;
        StagePanel.Visibility = Visibility.Collapsed;
        StartButton.Visibility = Visibility.Visible;
        StopButton.Visibility = Visibility.Collapsed;
        ProgressValue.Value = 0;
        _trayToggleItem.Text = "Подключиться";
        _trayIcon.Text = "Cloudflare Proxy — отключён";
        _sessionTimer.Stop();
        SessionTimeText.Text = "00:00:00";
        LatencyText.Text = "пинг: —";
        ResetStages();
    }

    private async Task RefreshExitInfoAsync(string endpoint)
    {
        _connectionInfoCancellation?.Cancel();
        _connectionInfoCancellation?.Dispose();
        _connectionInfoCancellation = CancellationTokenSource.CreateLinkedTokenSource(_shutdown.Token);
        var token = _connectionInfoCancellation.Token;

        ExitIpText.Text = "определяю…";
        ExitCountryText.Text = "определяю…";
        LatencyText.Text = "пинг: …";
        SetFlagVisual("--");
        try
        {
            var info = await ConnectionInfoService.QueryAsync(endpoint, token);
            if (token.IsCancellationRequested || !_proxyRunning)
                return;
            ExitIpText.Text = info.IpAddress;
            ExitCountryText.Text = info.CountryName;
            LatencyText.Text = $"пинг: {info.LatencyMs} мс";
            SetFlagVisual(info.CountryCode);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            if (!_proxyRunning)
                return;
            ExitIpText.Text = "нет данных";
            ExitCountryText.Text = "нет данных";
            LatencyText.Text = "пинг: —";
            SetFlagVisual("--");
            AppendLog("Не удалось определить IP и страну: " + exception.Message);
        }
    }

    private void SetFlagVisual(string countryCode)
    {
        var stripes = new[] { FlagStripe1, FlagStripe2, FlagStripe3 };
        if (DrawSpecialFlag(countryCode))
        {
            foreach (var stripe in stripes)
                stripe.Visibility = Visibility.Collapsed;
            SpecialFlagCanvas.Visibility = Visibility.Visible;
            FlagCodeOverlay.Visibility = Visibility.Collapsed;
            return;
        }

        SpecialFlagCanvas.Visibility = Visibility.Collapsed;
        foreach (var stripe in stripes)
            stripe.Visibility = Visibility.Visible;
        var known = Flags.TryGetValue(countryCode, out var definition);
        definition ??= new FlagDefinition("#159FD6", "#0C82B2", "#176181");
        var colors = new[] { definition.First, definition.Second, definition.Third };
        var weights = new[] { definition.FirstWeight, definition.SecondWeight, definition.ThirdWeight };

        for (var index = 0; index < stripes.Length; index++)
        {
            stripes[index].Background = BrushFromHex(colors[index]);
            if (definition.Vertical)
            {
                Grid.SetRow(stripes[index], 0);
                Grid.SetRowSpan(stripes[index], 3);
                Grid.SetColumn(stripes[index], index);
                Grid.SetColumnSpan(stripes[index], 1);
                FlagGrid.ColumnDefinitions[index].Width = new GridLength(weights[index], GridUnitType.Star);
                FlagGrid.RowDefinitions[index].Height = new GridLength(1, GridUnitType.Star);
            }
            else
            {
                Grid.SetRow(stripes[index], index);
                Grid.SetRowSpan(stripes[index], 1);
                Grid.SetColumn(stripes[index], 0);
                Grid.SetColumnSpan(stripes[index], 3);
                FlagGrid.RowDefinitions[index].Height = new GridLength(weights[index], GridUnitType.Star);
                FlagGrid.ColumnDefinitions[index].Width = new GridLength(1, GridUnitType.Star);
            }
        }

        FlagCodeOverlay.Text = countryCode;
        FlagCodeOverlay.Visibility = known ? Visibility.Collapsed : Visibility.Visible;
    }

    private bool DrawSpecialFlag(string countryCode)
    {
        SpecialFlagCanvas.Children.Clear();
        switch (countryCode.ToUpperInvariant())
        {
            case "US":
                DrawUnitedStatesFlag();
                return true;
            case "GB":
                DrawUnitedKingdomFlag();
                return true;
            case "CA":
                DrawCanadaFlag();
                return true;
            case "JP":
                AddFlagRectangle("#FFFFFF", 0, 0, 82, 58);
                AddFlagEllipse("#BC002D", 27, 15, 28, 28);
                return true;
            case "SE":
                DrawNordicFlag("#006AA7", "#FECC00", null);
                return true;
            case "FI":
                DrawNordicFlag("#FFFFFF", "#003580", null);
                return true;
            case "DK":
                DrawNordicFlag("#C60C30", "#FFFFFF", null);
                return true;
            case "NO":
                DrawNordicFlag("#BA0C2F", "#FFFFFF", "#00205B");
                return true;
            case "CH":
                AddFlagRectangle("#D52B1E", 0, 0, 82, 58);
                AddFlagRectangle("#FFFFFF", 34, 12, 14, 34);
                AddFlagRectangle("#FFFFFF", 24, 22, 34, 14);
                return true;
            default:
                return false;
        }
    }

    private void DrawUnitedStatesFlag()
    {
        const double stripeHeight = 58.0 / 13.0;
        for (var index = 0; index < 13; index++)
            AddFlagRectangle(index % 2 == 0 ? "#B22234" : "#FFFFFF", 0, index * stripeHeight, 82, stripeHeight + 0.2);
        AddFlagRectangle("#3C3B6E", 0, 0, 36, stripeHeight * 7);
        for (var row = 0; row < 5; row++)
        {
            var count = row % 2 == 0 ? 6 : 5;
            var offset = row % 2 == 0 ? 2.5 : 5.2;
            for (var column = 0; column < count; column++)
                AddFlagEllipse("#FFFFFF", offset + column * 5.8, 2.1 + row * 5.7, 1.8, 1.8);
        }
    }

    private void DrawUnitedKingdomFlag()
    {
        AddFlagRectangle("#012169", 0, 0, 82, 58);
        AddFlagLine("#FFFFFF", 0, 0, 82, 58, 11);
        AddFlagLine("#FFFFFF", 82, 0, 0, 58, 11);
        AddFlagLine("#C8102E", 0, 0, 82, 58, 4);
        AddFlagLine("#C8102E", 82, 0, 0, 58, 4);
        AddFlagRectangle("#FFFFFF", 0, 21, 82, 16);
        AddFlagRectangle("#FFFFFF", 33, 0, 16, 58);
        AddFlagRectangle("#C8102E", 0, 25, 82, 8);
        AddFlagRectangle("#C8102E", 37, 0, 8, 58);
    }

    private void DrawCanadaFlag()
    {
        AddFlagRectangle("#D80621", 0, 0, 20, 58);
        AddFlagRectangle("#FFFFFF", 20, 0, 42, 58);
        AddFlagRectangle("#D80621", 62, 0, 20, 58);
        var leaf = new Polygon
        {
            Fill = BrushFromHex("#D80621"),
            Points = new PointCollection
            {
                new(41, 11), new(45, 22), new(53, 18), new(49, 29), new(56, 32),
                new(45, 37), new(43, 48), new(39, 48), new(37, 37), new(26, 32),
                new(33, 29), new(29, 18), new(37, 22),
            },
        };
        SpecialFlagCanvas.Children.Add(leaf);
    }

    private void DrawNordicFlag(string background, string outerCross, string? innerCross)
    {
        AddFlagRectangle(background, 0, 0, 82, 58);
        AddFlagRectangle(outerCross, 24, 0, 12, 58);
        AddFlagRectangle(outerCross, 0, 23, 82, 12);
        if (innerCross is null)
            return;
        AddFlagRectangle(innerCross, 27, 0, 6, 58);
        AddFlagRectangle(innerCross, 0, 26, 82, 6);
    }

    private void AddFlagRectangle(string color, double left, double top, double width, double height)
    {
        var rectangle = new System.Windows.Shapes.Rectangle { Fill = BrushFromHex(color), Width = width, Height = height };
        Canvas.SetLeft(rectangle, left);
        Canvas.SetTop(rectangle, top);
        SpecialFlagCanvas.Children.Add(rectangle);
    }

    private void AddFlagEllipse(string color, double left, double top, double width, double height)
    {
        var ellipse = new Ellipse { Fill = BrushFromHex(color), Width = width, Height = height };
        Canvas.SetLeft(ellipse, left);
        Canvas.SetTop(ellipse, top);
        SpecialFlagCanvas.Children.Add(ellipse);
    }

    private void AddFlagLine(string color, double x1, double y1, double x2, double y2, double thickness) =>
        SpecialFlagCanvas.Children.Add(new Line
        {
            X1 = x1, Y1 = y1, X2 = x2, Y2 = y2,
            Stroke = BrushFromHex(color), StrokeThickness = thickness,
        });

    private static SolidColorBrush BrushFromHex(string value) =>
        new((MediaColor)System.Windows.Media.ColorConverter.ConvertFromString(value));

    private void ShowError(string message)
    {
        Dispatcher.Invoke(() =>
        {
            StatusTitle.Text = _proxyRunning ? "Ошибка управления прокси" : "Не удалось подключиться";
            StatusMessage.Text = message;
            StatusMessage.Visibility = Visibility.Visible;
            ConnectedFactsPanel.Visibility = Visibility.Collapsed;
            if (!_proxyRunning)
            {
                FlagPlate.Visibility = Visibility.Collapsed;
                OfflineArtwork.Visibility = Visibility.Visible;
            }
            BusyArtwork.Visibility = Visibility.Collapsed;
            StagePanel.Visibility = Visibility.Collapsed;
            StageRow.Height = new GridLength(72);
            EndpointCard.Visibility = _proxyRunning ? Visibility.Visible : Visibility.Collapsed;
            StartButton.Visibility = _proxyRunning ? Visibility.Collapsed : Visibility.Visible;
            StopButton.Visibility = _proxyRunning ? Visibility.Visible : Visibility.Collapsed;
            AppendLog("ERROR: " + message);
        });
    }

    private void SetBusy(bool busy, string? message = null)
    {
        StartButton.IsEnabled = !busy;
        StopButton.IsEnabled = !busy;
        _trayToggleItem.Enabled = !busy;
        if (busy)
        {
            FlagPlate.Visibility = Visibility.Collapsed;
            OfflineArtwork.Visibility = Visibility.Collapsed;
            BusyArtwork.Visibility = Visibility.Visible;
            ConnectedFactsPanel.Visibility = Visibility.Collapsed;
            StatusMessage.Visibility = Visibility.Visible;
            EndpointCard.Visibility = Visibility.Collapsed;
            StagePanel.Visibility = Visibility.Visible;
        }
        else if (_proxyRunning)
        {
            FlagPlate.Visibility = Visibility.Visible;
            OfflineArtwork.Visibility = Visibility.Collapsed;
            BusyArtwork.Visibility = Visibility.Collapsed;
            ConnectedFactsPanel.Visibility = Visibility.Visible;
            StatusMessage.Visibility = Visibility.Collapsed;
            EndpointCard.Visibility = Visibility.Visible;
            StagePanel.Visibility = Visibility.Collapsed;
        }
        if (message is not null)
            StatusMessage.Text = message;
    }

    private void UpdateStages(int progress)
    {
        SetStage(StageCheck, progress >= 8, progress is > 0 and < 18);
        SetStage(StageGithub, progress >= 28, progress is >= 18 and < 40);
        SetStage(StageWorkflow, progress >= 52, progress is >= 40 and < 52);
        SetStage(StageRunner, progress >= 68, progress is >= 52 and < 68);
        SetStage(StageTunnel, progress >= 84, progress is >= 68 and < 84);
        SetStage(StageLocal, progress >= 100, progress is >= 84 and < 100);
    }

    private static void SetStage(TextBlock block, bool complete, bool active)
    {
        var label = block.Text.Length > 3 ? block.Text.Substring(3) : block.Text;
        block.Text = (complete ? "✓  " : active ? "●  " : "○  ") + label;
        block.Foreground = complete ? SuccessBrush : active ? ActiveBrush : MutedBrush;
    }

    private void ResetStages()
    {
        GithubAuthPanel.Visibility = Visibility.Collapsed;
        GithubAuthCodeText.Text = string.Empty;
        CopyGithubCodeButton.Content = "Скопировать код";
        StageRow.Height = new GridLength(72);
        StageCheck.Text = "○  Проверка";
        StageGithub.Text = "○  GitHub";
        StageWorkflow.Text = "○  Workflow";
        StageRunner.Text = "○  Runner";
        StageTunnel.Text = "○  Tunnel";
        StageLocal.Text = "○  SOCKS5";
        foreach (var stage in new[] { StageCheck, StageGithub, StageWorkflow, StageRunner, StageTunnel, StageLocal })
            stage.Foreground = MutedBrush;
    }

    private void AppendLog(string line)
    {
        Dispatcher.Invoke(() =>
        {
            if (string.IsNullOrWhiteSpace(line))
                return;
            if (line.IndexOf("Enter this code:", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                StatusTitle.Text = "Подтвердите вход в GitHub";
                var marker = line.IndexOf("Enter this code:", StringComparison.OrdinalIgnoreCase);
                StatusMessage.Text = marker >= 0
                    ? line.Substring(0, marker) + "Код: " + line.Substring(marker + "Enter this code:".Length)
                    : line;
                StatusMessage.Visibility = Visibility.Visible;
            }
            LogText.AppendText((LogText.Text.Length == 0 ? "" : Environment.NewLine) + line);
            if (LogText.Text.Length > 16000)
                LogText.Text = LogText.Text.Substring(LogText.Text.Length - 12000);
            LogText.ScrollToEnd();
        });
    }

    private void CopyEndpoint_Click(object sender, RoutedEventArgs e)
    {
        WpfClipboard.SetText(EndpointText.Text);
        LatencyText.Text = "адрес скопирован";
    }

    private void CopyGithubCode_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(GithubAuthCodeText.Text))
            return;

        try
        {
            WpfClipboard.SetText(GithubAuthCodeText.Text.Trim());
            CopyGithubCodeButton.Content = "Скопировано ✓";
        }
        catch (Exception exception)
        {
            AppendLog("Не удалось скопировать код GitHub: " + exception.Message);
            CopyGithubCodeButton.Content = "Повторить";
        }
    }

    private void SelectableText_GotKeyboardFocus(object sender, KeyboardFocusChangedEventArgs e)
    {
        if (sender is System.Windows.Controls.TextBox textBox)
            Dispatcher.BeginInvoke(textBox.SelectAll);
    }

    private void SelectableText_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (sender is not System.Windows.Controls.TextBox textBox)
            return;
        textBox.SelectAll();
        e.Handled = true;
    }

    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        if (_controller.IsBusy)
        {
            System.Windows.MessageBox.Show(this, "Дождитесь завершения текущей операции.", "Настройки временно недоступны",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        PopulateEmbeddedSettings(_settings);
        MainContent.Visibility = Visibility.Collapsed;
        SettingsPage.Visibility = Visibility.Visible;
    }

    private void PopulateEmbeddedSettings(AppSettings settings)
    {
        SettingsStartWithWindowsBox.IsChecked = settings.StartWithWindows;
        SettingsStartInTrayBox.IsChecked = settings.StartInTray;
        SettingsConnectOnStartupBox.IsChecked = settings.ConnectOnStartup;
        SettingsShowNotificationsBox.IsChecked = settings.ShowTrayNotifications;
        SettingsCheckExitInfoBox.IsChecked = settings.CheckExitInfo;
        SettingsListenAddressBox.Text = settings.ListenAddress;
        SettingsListenPortBox.Text = settings.ListenPort.ToString();
        RefreshEmbeddedSettingsControls();
    }

    private void BackFromSettings_Click(object sender, RoutedEventArgs e) => CloseEmbeddedSettings();

    private void CloseEmbeddedSettings()
    {
        SettingsPage.Visibility = Visibility.Collapsed;
        MainContent.Visibility = Visibility.Visible;
    }

    private void EmbeddedStartup_Changed(object sender, RoutedEventArgs e) => RefreshEmbeddedSettingsControls();
    private void EmbeddedAddress_Changed(object sender, RoutedEventArgs e) => RefreshEmbeddedSettingsControls();
    private void EmbeddedAddress_LostFocus(object sender, KeyboardFocusChangedEventArgs e) => RefreshEmbeddedSettingsControls();

    private void RefreshEmbeddedSettingsControls()
    {
        if (!IsInitialized || SettingsStartInTrayBox is null)
            return;
        SettingsStartInTrayBox.IsEnabled = SettingsStartWithWindowsBox.IsChecked == true;
        EmbeddedNetworkWarning.Visibility = SettingsListenAddressBox.Text.Trim() == "0.0.0.0"
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    private void ResetEmbeddedSettings_Click(object sender, RoutedEventArgs e) =>
        PopulateEmbeddedSettings(new AppSettings());

    private async void SaveEmbeddedSettings_Click(object sender, RoutedEventArgs e)
    {
        var addressText = SettingsListenAddressBox.Text.Trim();
        if (!IPAddress.TryParse(addressText, out var address) || address.AddressFamily != AddressFamily.InterNetwork)
        {
            System.Windows.MessageBox.Show(this, "Укажите корректный IPv4-адрес.", "Неверный IP-адрес",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            SettingsListenAddressBox.Focus();
            return;
        }
        if (!int.TryParse(SettingsListenPortBox.Text.Trim(), out var port) || port is < 1 or > 65535)
        {
            System.Windows.MessageBox.Show(this, "Порт должен быть числом от 1 до 65535.", "Неверный порт",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            SettingsListenPortBox.Focus();
            return;
        }

        var previous = _settings.Copy();
        var updated = new AppSettings
        {
            StartWithWindows = SettingsStartWithWindowsBox.IsChecked == true,
            StartInTray = SettingsStartInTrayBox.IsChecked == true,
            ConnectOnStartup = SettingsConnectOnStartupBox.IsChecked == true,
            ShowTrayNotifications = SettingsShowNotificationsBox.IsChecked == true,
            CheckExitInfo = SettingsCheckExitInfoBox.IsChecked == true,
            ListenAddress = address.ToString(),
            ListenPort = port,
        };

        try
        {
            SettingsService.Save(updated);
        }
        catch (Exception exception)
        {
            System.Windows.MessageBox.Show(this, "Не удалось сохранить настройки:\n" + exception.Message, "Ошибка настроек",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        CloseEmbeddedSettings();

        var endpointChanged = previous.ListenAddress != updated.ListenAddress ||
                              previous.ListenPort != updated.ListenPort;
        var wasRunning = _proxyRunning;
        if (endpointChanged && wasRunning)
        {
            await StopProxyAsync();
            if (_proxyRunning)
            {
                try { SettingsService.Save(previous); } catch { }
                System.Windows.MessageBox.Show(this, "Прокси не остановился, поэтому новый IP и порт не применены.",
                    "Перезапуск не выполнен", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
        }

        _settings = updated;
        _controller.ConfigureEndpoint(_settings.ListenAddress, _settings.ListenPort);
        _trayHintShown = false;

        if (endpointChanged && wasRunning)
        {
            await StartProxyAsync();
            return;
        }

        if (_proxyRunning)
        {
            if (_settings.CheckExitInfo)
                _ = RefreshExitInfoAsync(EndpointText.Text);
            else
            {
                _connectionInfoCancellation?.Cancel();
                ExitIpText.Text = "отключено";
                ExitCountryText.Text = "отключено";
                LatencyText.Text = "пинг: —";
                SetFlagVisual("--");
            }
        }
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState == MouseButtonState.Pressed)
            DragMove();
    }

    private async Task ToggleProxyFromTrayAsync()
    {
        if (_controller.IsBusy)
            return;
        if (_proxyRunning)
            await StopProxyAsync();
        else
            await StartProxyAsync();
    }

    private void Window_StateChanged(object? sender, EventArgs e)
    {
        if (WindowState == WindowState.Maximized)
        {
            WindowState = WindowState.Normal;
            return;
        }
        if (WindowState == WindowState.Minimized)
            HideToTray();
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (_allowExit)
            return;
        e.Cancel = true;
        HideToTray();
    }

    private void HideToTray(bool showHint = true)
    {
        WindowState = WindowState.Normal;
        ShowInTaskbar = false;
        Hide();
        if (showHint && _settings.ShowTrayNotifications && !_trayHintShown)
        {
            _trayIcon.ShowBalloonTip(2500, "Cloudflare Proxy",
                "Приложение продолжает работать в системном трее.", Forms.ToolTipIcon.Info);
            _trayHintShown = true;
        }
    }

    private void RestoreFromTray()
    {
        ShowInTaskbar = true;
        Show();
        WindowState = WindowState.Normal;
        Activate();
        Topmost = true;
        Topmost = false;
        Focus();
    }

    private void ExitApplication()
    {
        _allowExit = true;
        Close();
    }

    private void CapturePreviewIfRequested()
    {
        var path = Environment.GetEnvironmentVariable("CLOUDFLARE_PROXY_UI_PREVIEW");
        if (string.IsNullOrWhiteSpace(path))
            return;
        try
        {
            var dpi = VisualTreeHelper.GetDpi(this);
            var bitmap = new RenderTargetBitmap(
                (int)Math.Ceiling(ActualWidth * dpi.DpiScaleX),
                (int)Math.Ceiling(ActualHeight * dpi.DpiScaleY),
                96 * dpi.DpiScaleX,
                96 * dpi.DpiScaleY,
                PixelFormats.Pbgra32);
            bitmap.Render(this);
            var encoder = new PngBitmapEncoder();
            encoder.Frames.Add(BitmapFrame.Create(bitmap));
            using var stream = File.Create(System.IO.Path.GetFullPath(path));
            encoder.Save(stream);
        }
        catch (Exception exception)
        {
            AppendLog("Не удалось сохранить preview: " + exception.Message);
        }
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => HideToTray();
    private void Close_Click(object sender, RoutedEventArgs e) => HideToTray();
}

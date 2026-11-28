using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Platform;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using System.Runtime.InteropServices;
using UTCie.Linux;

namespace UTCIEID.App;

public partial class MainWindow : Window
{
    private IInputPane? _inputPane;
    private readonly Grid _page;
    private readonly TextBox _pinInput;
    private WriteableBitmap? _cameraBitmap;
    private QrCameraScanner? _cameraScanner;
    public MainWindow()
    {
        AvaloniaXamlLoader.Load(this);
        _page = this.FindControl<Grid>("Page")!;
        _pinInput = this.FindControl<TextBox>("PinInput")!;
        Opened += OnOpened;
        Deactivated += (_, _) => (DataContext as MainViewModel)?.OnDeactivated();
        Closed += (_, _) =>
        {
            (DataContext as MainViewModel)?.OnDeactivated();
            if (DataContext is MainViewModel model) model.CardDetected -= OnCardDetected;
            if (_inputPane is not null) _inputPane.StateChanged -= OnInputPaneChanged;
        };
        this.FindControl<TextBox>("CanInput")!.GotFocus += (_, _) => Dispatcher.UIThread.Post(() => this.FindControl<TextBox>("CanInput")!.BringIntoView(), DispatcherPriority.Background);
        _pinInput.GotFocus += (_, _) => Dispatcher.UIThread.Post(() => _pinInput.BringIntoView(), DispatcherPriority.Background);
        foreach (string name in new[] { "VaultPasswordInput", "VaultConfirmationInput" })
        {
            var field = this.FindControl<TextBox>(name)!;
            field.GotFocus += (_, _) => Dispatcher.UIThread.Post(() => field.BringIntoView(), DispatcherPriority.Background);
        }
    }

    private async void OnOpened(object? sender, EventArgs e)
    {
        _inputPane = InputPane;
        Console.Error.WriteLine($"UTCIEID input pane: {_inputPane?.GetType().Name ?? "unavailable"}; window active: {IsActive}");
        if (_inputPane is not null) _inputPane.StateChanged += OnInputPaneChanged;
        if (DataContext is MainViewModel model)
        {
            model.CardDetected += OnCardDetected;
            model.ReadCameraQrAsync = async token =>
            {
                _cameraScanner = new QrCameraScanner();
                try { return await _cameraScanner.ScanAsync(ShowCameraFrameAsync, token); }
                finally
                {
                    _cameraScanner = null;
                    this.FindControl<Image>("CameraPreview")!.Source = null;
                    _cameraBitmap?.Dispose(); _cameraBitmap = null;
                }
            };
            model.OpenUriAsync = uri => Environment.GetEnvironmentVariable("APP_ID") is not null
                ? LomiriUrlLauncher.OpenAsync(uri) : Launcher.LaunchUriAsync(uri);
            await model.RefreshAsync();
            if (Program.StartupQrImage is { } path)
            {
                try
                {
                    await using var stream = File.OpenRead(path);
                    model.AcceptQrLink(await QrImageReader.ReadAsync(stream));
                }
                catch { model.AcceptQrLink(""); }
            }
        }
    }

    private static void OnCardDetected() => _ = LomiriHaptics.CardDetectedAsync();

    private void OnCameraTapped(object? sender, RoutedEventArgs e) => _cameraScanner?.RequestFocus();

    private async Task ShowCameraFrameAsync(CameraFrame frame, CancellationToken token)
    {
        var converted = frame.ToBgra();
        try
        {
            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                if (token.IsCancellationRequested || DataContext is not MainViewModel { ScanningQr: true }) return;
                var preview = this.FindControl<Image>("CameraPreview")!;
                if (_cameraBitmap?.PixelSize != new PixelSize(converted.Width, converted.Height))
                {
                    preview.Source = null; _cameraBitmap?.Dispose();
                    _cameraBitmap = new WriteableBitmap(new PixelSize(converted.Width, converted.Height), new Vector(96, 96), PixelFormat.Bgra8888, AlphaFormat.Opaque);
                    preview.Source = _cameraBitmap;
                }
                using (var buffer = _cameraBitmap.Lock())
                    for (int y = 0; y < converted.Height; y++)
                        Marshal.Copy(converted.Pixels, y * converted.Width * 4, buffer.Address + y * buffer.RowBytes, converted.Width * 4);
                preview.InvalidateVisual();
            });
        }
        finally { Array.Clear(converted.Pixels); }
    }

    private void OnInputPaneChanged(object? sender, InputPaneStateEventArgs e)
    {
        var rect = _inputPane?.OccludedRect ?? default;
        double inset = rect.Height > 0 && rect.Bottom >= Bounds.Height - 1 ? Math.Max(0, Bounds.Height - rect.Top) : 0;
        _page.Margin = new Thickness(0, 0, 0, inset);
        Dispatcher.UIThread.Post(() =>
        {
            if (FocusManager?.GetFocusedElement() is Control control) control.BringIntoView();
        }, DispatcherPriority.Background);
    }
}

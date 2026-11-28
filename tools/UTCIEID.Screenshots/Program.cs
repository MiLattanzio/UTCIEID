using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using Avalonia.VisualTree;
using SkiaSharp;
using UTCIEID.App;
using UTCie.Sdk.Card;

// Renders the actual AXAML UI with synthetic, memory-only fixtures. This tool
// is never shipped in the Click. No camera, NFC, keyring, browser or network.
string output = Path.GetFullPath(args.Single());
Directory.CreateDirectory(output);
AppBuilder.Configure<App>().UseSkia().WithInterFont()
    .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
    .SetupWithoutStarting();

var reader = new DemoReader();
var empty = new MainViewModel(reader, credentials: new DemoStore(false));
var window = Open(empty);
Capture(window, "01-cie.png");
window.Close();

var model = new MainViewModel(reader, credentials: new DemoStore(true));
window = Open(model);
model.SelectedTab = 1;
const string request = "https://idserver.servizicie.interno.gov.it/idp/erroreQr.jsp?opId=_UTCIEID_SCREENSHOT_DEMO&opType=login&SPName=https://example.org&IdPName=https://idserver.servizicie.interno.gov.it/idp/&userId=CA00000AA&opText=Servizio dimostrativo";
model.ReadCameraQrAsync = _ => Task.FromResult<string?>(request);
model.ScanQrCommand.Execute(null);
Capture(window, "02-accesso-qr.png");
window.Close();

model = new MainViewModel(reader, credentials: new DemoStore(true));
window = Open(model);
model.SelectedTab = 2;
Capture(window, "03-dati-dimostrativi.png");
var certificate = window.GetVisualDescendants().OfType<Expander>()
    .Single(e => Equals(e.Header, "Certificato di autenticazione"));
certificate.IsExpanded = true;
Dispatcher.UIThread.RunJobs();
certificate.BringIntoView();
Capture(window, "04-certificato-dimostrativo.png");
window.Close();

model = new MainViewModel(reader, credentials: new DemoStore(false));
window = Open(model);
model.VaultPanelOpen = true;
Capture(window, "05-archivio-cifrato.png");
window.Close();
Console.WriteLine("Rendered 5 AXAML screenshots with synthetic data only.");

MainWindow Open(MainViewModel viewModel)
{
    var view = new MainWindow { DataContext = viewModel, Width = 408, Height = 865,
        WindowDecorations = WindowDecorations.None };
    view.Show();
    Dispatcher.UIThread.RunJobs();
    foreach (var text in view.GetVisualDescendants().OfType<TextBlock>().Where(t => t.Text == "ANTEPRIMA"))
        text.Text = "DEMO";
    return view;
}

void Capture(MainWindow view, string file)
{
    // Settle styles/animations before capturing; no camera or real device is involved.
    Dispatcher.UIThread.RunJobs();
    AvaloniaHeadlessPlatform.ForceRenderTimerTick();
    Thread.Sleep(250);
    AvaloniaHeadlessPlatform.ForceRenderTimerTick();
    Dispatcher.UIThread.RunJobs();
    view.UpdateLayout();
    // Render at 3x for the same 1224x2595 content size used on the Fairphone.
    using var bitmap = new RenderTargetBitmap(new PixelSize(1224, 2595), new Vector(288, 288));
    bitmap.Render(view);
    bitmap.Save(Path.Combine(output, file), new PngBitmapEncoderOptions());
}

sealed class DemoReader : ICardReader
{
    public Task<ReaderStatus> GetStatusAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(new ReaderStatus(true, true, "NFC pronto · dimostrazione"));
    public Task<ICardTransport> WaitForCardAsync(CancellationToken cancellationToken = default) =>
        throw new InvalidOperationException("The screenshot renderer cannot access NFC.");
}

sealed class DemoStore : ILocalVault
{
    private readonly RegisteredCard? _card;
    private readonly CardProfile? _profile;
    public bool Exists => _card is not null;
    public bool IsUnlocked { get; private set; }
    public bool HasSavedPin => IsUnlocked && Exists;
    public DemoStore(bool registered)
    {
        if (!registered) return;
        IsUnlocked = true;
        _card = new(new string('0', 64));
        using var rsa = RSA.Create(2048);
        var name = new X500DistinguishedName("CN=DATI DIMOSTRATIVI, SERIALNUMBER=IDCIT-DEMO00000, G=Esempio, SN=DIMOSTRATIVO, C=IT");
        var certificateRequest = new CertificateRequest(name, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = certificateRequest.CreateSelfSigned(
            new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero));
        using var portrait = new SKSurfaceHolder();
        var document = new IcaoDocument("Esempio", "DIMOSTRATIVO", "DEMO00000", "000101", "300101", "ITA", "X",
            new string('<', 90), portrait.Jpeg, "image/jpeg", [], DateTimeOffset.UnixEpoch);
        _profile = new(_card.ServiceIdHash, certificate.RawData, DateTimeOffset.UnixEpoch, document);
    }
    public Task<RegisteredCard?> GetRegistrationAsync(CancellationToken token = default) => Task.FromResult(_card);
    public Task<CardProfile?> GetProfileAsync(RegisteredCard card, CancellationToken token = default) => Task.FromResult(_profile is null ? null : _profile with
        { CertificateDer = _profile.CertificateDer.ToArray(), Document = _profile.Document! with { Portrait = _profile.Document.Portrait.ToArray(), Sod = _profile.Document.Sod.ToArray() } });
    public Task CreateAsync(ReadOnlyMemory<char> passphrase, CancellationToken token = default) => throw NoSecrets();
    public Task UnlockAsync(ReadOnlyMemory<char> passphrase, CancellationToken token = default) => throw NoSecrets();
    public void Lock() => IsUnlocked = false;
    public Task SaveCardAsync(CardProfile profile, ReadOnlyMemory<char> pin, CancellationToken token = default) => throw NoSecrets();
    public Task RemovePinAsync(CancellationToken token = default) => throw NoSecrets();
    public Task DeleteAsync(CancellationToken token = default) => throw NoSecrets();
    public Task<char[]> GetPinAsync(RegisteredCard card, CancellationToken token = default) => throw NoSecrets();
    public Task SaveAsync(RegisteredCard card, ReadOnlyMemory<char> pin, CancellationToken token = default) => throw NoSecrets();
    public Task ForgetAsync(RegisteredCard card, CancellationToken token = default) => throw NoSecrets();
    public Task SaveProfileAsync(CardProfile profile, CancellationToken token = default) => throw NoSecrets();
    public Task DeleteProfileAsync(RegisteredCard card, CancellationToken token = default) => throw NoSecrets();
    private static InvalidOperationException NoSecrets() => new("Synthetic screenshot fixtures cannot read or write credentials.");
}

sealed class SKSurfaceHolder : IDisposable
{
    private readonly SKSurface _surface = SKSurface.Create(new SKImageInfo(300, 380));
    public byte[] Jpeg { get; }
    public SKSurfaceHolder()
    {
        _surface.Canvas.Clear(new SKColor(221, 238, 235));
        using var paint = new SKPaint { Color = new SKColor(111, 156, 149), IsAntialias = true };
        _surface.Canvas.DrawCircle(150, 116, 57, paint);
        _surface.Canvas.DrawRoundRect(new SKRect(43, 190, 257, 350), 60, 60, paint);
        using var snapshot = _surface.Snapshot();
        using var data = snapshot.Encode(SKEncodedImageFormat.Jpeg, 95);
        Jpeg = data.ToArray();
    }
    public void Dispose() => _surface.Dispose();
}

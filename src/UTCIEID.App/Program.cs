using Avalonia;
using UTCie.Linux;
using UTCie.Sdk.Card;

namespace UTCIEID.App;

internal static class Program
{
    internal static string? StartupLink { get; private set; }
    internal static string? StartupQrImage { get; private set; }
    [STAThread]
    public static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "--probe-qr-file")
        {
            try
            {
                using var stream = File.OpenRead(args[1]);
                var link = QrImageReader.ReadAsync(stream).GetAwaiter().GetResult();
                _ = UTCie.Sdk.Authentication.CieQrAuthenticationRequest.Parse(link, UTCie.Sdk.Authentication.CieEnvironment.Production);
                Console.WriteLine("QR CIE con OTP decodificato e validato. Parametri omessi; nessun accesso di rete o NFC.");
                return 0;
            }
            catch (Exception e) { Console.Error.WriteLine($"Immagine QR CIE non valida ({e.GetType().Name})."); return 2; }
        }
        if (args.Contains("--probe-nfc")) return ProbeAsync().GetAwaiter().GetResult();
        if (args.Contains("--probe-keyring")) return ProbeKeyringAsync().GetAwaiter().GetResult();
        if (args.Contains("--read-card-id")) return ReadIdAsync().GetAwaiter().GetResult();
        if (args.Contains("--probe-card-channel")) return ProbeChannelAsync().GetAwaiter().GetResult();
        StartupLink = args.FirstOrDefault(a => a.StartsWith("https://", StringComparison.Ordinal) || a.StartsWith("utcieid://", StringComparison.Ordinal));
        int qrArgument = Array.IndexOf(args, "--qr-file");
        if (qrArgument >= 0 && qrArgument + 1 < args.Length) StartupQrImage = args[qrArgument + 1];
        var builder = BuildAvaloniaApp();
        if (args.Contains("--wayland")) builder.UseWayland();
        return builder.StartWithClassicDesktopLifetime(args);
    }

    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>().UsePlatformDetect().WithInterFont()
        .LogToDelegate(message =>
        {
            // The native input adapter logs only the exception type, never editor content.
            if (message.Contains("Maliit input unavailable", StringComparison.Ordinal)) Console.Error.WriteLine(message);
            if (message.Contains("Unable to connect to DBus", StringComparison.Ordinal)) Console.Error.WriteLine("UTCIEID: session D-Bus connection failed.");
        }, Avalonia.Logging.LogEventLevel.Warning, Avalonia.Logging.LogArea.Platform, "DBUS");

    private static async Task<int> ProbeAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            var status = await new NfcdReader().GetStatusAsync(timeout.Token);
            Console.WriteLine(status.Description);
            return status.Enabled ? 0 : 2;
        }
        catch { Console.Error.WriteLine("Diagnostica NFC non riuscita."); return 2; }
    }

    private static async Task<int> ReadIdAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        try
        {
            Console.WriteLine("Avvicina la CIE. Nessun PIN richiesto; identificativo omesso dall'output.");
            await using var card = new CieCard(await new NfcdReader().WaitForCardAsync(timeout.Token));
            await card.ReadServiceIdAsync(timeout.Token);
            Console.WriteLine("CIE riconosciuta: file servizi letto correttamente (12 byte, dati omessi).");
            return 0;
        }
        catch (CardException e) { Console.Error.WriteLine(e.Message); return 2; }
        catch { Console.Error.WriteLine("Carta non letta: timeout, rimozione o servizio NFC non disponibile."); return 2; }
    }

    private static async Task<int> ProbeKeyringAsync()
    {
        string root = Environment.GetEnvironmentVariable("XDG_CACHE_HOME") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".cache");
        string directory = Path.Combine(root, "utcieid.milattanzio", "keyring-probe-" + Guid.NewGuid().ToString("N"));
        var store = new SecretServicePinStore(directory);
        var card = new RegisteredCard(Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));
        char[] pin = "12345678".ToCharArray();
        try
        {
            await store.SaveAsync(card, pin);
            using var rsa = System.Security.Cryptography.RSA.Create(2048);
            var request = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=UTCIEID SYNTHETIC TEST", rsa,
                System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            var profile = new CardProfile(card.ServiceIdHash, cert.RawData, DateTimeOffset.UtcNow);
            await store.SaveProfileAsync(profile);
            var reloadedProfile = await new SecretServicePinStore(directory).GetProfileAsync(card);
            if (reloadedProfile is null || !reloadedProfile.CertificateDer.AsSpan().SequenceEqual(profile.CertificateDer)) throw new InvalidOperationException();
            var loaded = await store.GetPinAsync(card);
            try { if (!loaded.AsSpan().SequenceEqual(pin)) throw new InvalidOperationException(); }
            finally { Array.Clear(loaded); }
            await store.ForgetAsync(card);
            if (await store.GetProfileAsync(card) is not null) throw new InvalidOperationException();
            Console.WriteLine("Portachiavi: PIN e certificato sintetici salvati, riletti separatamente e rimossi. Dati reali non modificati.");
            return 0;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine(e is CredentialStoreException ? e.Message : "Verifica del portachiavi non riuscita.");
            return 2;
        }
        finally
        {
            Array.Clear(pin);
            // This unique test attribute never selects real registrations.
            try { await store.ForgetAsync(card); } catch { }
            if (Directory.Exists(directory)) Directory.Delete(directory, true);
        }
    }

    private static async Task<int> ProbeChannelAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(120));
        try
        {
            Console.WriteLine("Diagnostica canale senza PIN. Dati APDU omessi.");
            var transport = await new NfcdReader().WaitForCardAsync(timeout.Token);
            _ = LomiriHaptics.CardDetectedAsync();
            await using var card = new CieCard(new NoPinDiagnosticTransport(transport));
            await card.ReadServiceIdAsync(timeout.Token);
            await card.ProbeSecureChannelAsync(timeout.Token);
            Console.WriteLine("Canale DH/DAPP verificato. Nessun PIN inviato.");
            return 0;
        }
        catch (CardException e) { Console.Error.WriteLine(e.Message); return 2; }
        catch (Exception e) { Console.Error.WriteLine($"Diagnostica interrotta ({e.GetType().Name})."); return 2; }
    }

    private sealed class NoPinDiagnosticTransport(ICardTransport inner) : ICardTransport
    {
        public async ValueTask<byte[]> TransceiveAsync(ReadOnlyMemory<byte> command, CancellationToken token)
        {
            var apdu = ApduCommand.Parse(command.Span);
            if (apdu.Ins == 0x20) throw new InvalidOperationException("VERIFY PIN vietato nella diagnostica.");
            var response = await inner.TransceiveAsync(command, token);
            if (response.Length >= 2)
                Console.WriteLine($"APDU {apdu.Cla:X2}{apdu.Ins:X2}{apdu.P1:X2}{apdu.P2:X2}: SW={response[^2]:X2}{response[^1]:X2}, dati={response.Length - 2} byte (omessi)");
            return response;
        }
        public ValueTask DisposeAsync() => inner.DisposeAsync();
    }
}

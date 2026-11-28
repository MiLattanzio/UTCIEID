using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using UTCie.Linux;
using UTCie.Sdk.Card;

namespace UTCIEID.App;

// Uses a separate, random directory and synthetic data only; never opens the user's vault.
internal static class VaultProbe
{
    internal static async Task<int> RunAsync()
    {
        string root = Environment.GetEnvironmentVariable("XDG_CACHE_HOME") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".cache");
        string directory = Path.Combine(root, "utcieid.milattanzio", "vault-probe-" + Guid.NewGuid().ToString("N"));
        char[] password = "UTCIEID synthetic vault probe".ToCharArray(), pin = "12345678".ToCharArray();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        try
        {
            using var vault = new EncryptedCardVault(directory);
            var clock = Stopwatch.StartNew();
            await vault.CreateAsync(password, deadline.Token);
            long createMs = clock.ElapsedMilliseconds;
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=UTCIEID SYNTHETIC TEST", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            var card = new RegisteredCard(new string('A', 64));
            var profile = new CardProfile(card.ServiceIdHash, cert.RawData, DateTimeOffset.UtcNow);
            await vault.SaveCardAsync(profile, pin, deadline.Token);
            vault.Lock();
            using var reopened = new EncryptedCardVault(directory);
            try { await reopened.UnlockAsync("wrong synthetic passphrase".AsMemory(), deadline.Token); throw new InvalidOperationException(); }
            catch (CredentialStoreException) { }
            clock.Restart();
            await reopened.UnlockAsync(password, deadline.Token);
            long unlockMs = clock.ElapsedMilliseconds;
            var loaded = await reopened.GetPinAsync(card, deadline.Token);
            try { if (!loaded.AsSpan().SequenceEqual(pin)) throw new InvalidOperationException(); }
            finally { Array.Clear(loaded); }
            var saved = await reopened.GetProfileAsync(card, deadline.Token);
            if (saved is null || !saved.CertificateDer.AsSpan().SequenceEqual(cert.RawData)) throw new InvalidOperationException();
            await reopened.RemovePinAsync(deadline.Token);
            if (reopened.HasSavedPin || await reopened.GetProfileAsync(card, deadline.Token) is null) throw new InvalidOperationException();
            await reopened.DeleteAsync(deadline.Token);
            Console.WriteLine($"Archivio sintetico: creazione {createMs} ms, sblocco {unlockMs} ms; passphrase errata respinta, PIN e certificato riletti, PIN rimosso separatamente, archivio eliminato. Dati reali non toccati.");
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine($"Verifica archivio non riuscita ({e.GetType().Name}). Nessun dato reale usato."); return 2; }
        finally { Array.Clear(password); Array.Clear(pin); if (Directory.Exists(directory)) Directory.Delete(directory, true); }
    }
}

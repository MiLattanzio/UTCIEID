using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using UTCie.Sdk.Authentication;
using UTCie.Sdk.Card;

namespace UTCie.Sdk;

public enum CieProgress { WaitingForCard, CardDetected, OpeningSecureChannel, ReadingCertificate, RequestingChallenge, Signing, Completed, OpeningDocument, ReadingDocument, AuthenticatingTls, ReceivingOtp }
public sealed record CieCertificateInfo(string Subject, string Issuer, DateTime NotAfter, string ServiceIdHash, byte[] CertificateDer);

public sealed class CieClient(ICardReader reader)
{
    public async Task<CieCertificateInfo> ReadCertificateAsync(ReadOnlyMemory<char> pin, IProgress<CieProgress>? progress = null, CancellationToken token = default, string? expectedCardHash = null)
    {
        ValidatePin(pin);
        progress?.Report(CieProgress.WaitingForCard);
        await using var card = new CieCard(await reader.WaitForCardAsync(token).ConfigureAwait(false));
        progress?.Report(CieProgress.CardDetected);
        var cardHash = await CheckCardAsync(card, expectedCardHash, token).ConfigureAwait(false);
        progress?.Report(CieProgress.OpeningSecureChannel);
        await card.OpenSecureChannelAsync(pin, token).ConfigureAwait(false);
        progress?.Report(CieProgress.ReadingCertificate);
        using var certificate = X509CertificateLoader.LoadCertificate(await card.ReadCertificateAsync(token).ConfigureAwait(false));
        progress?.Report(CieProgress.Completed);
        return new(certificate.GetNameInfo(X509NameType.SimpleName, false), certificate.Issuer, certificate.NotAfter, cardHash, certificate.RawData);
    }

    public async Task<Uri> AuthenticateAsync(CieAuthenticationRequest request, ReadOnlyMemory<char> pin,
        ICieIdentityProvider provider, IProgress<CieProgress>? progress = null, CancellationToken token = default, string? expectedCardHash = null)
    {
        ValidatePin(pin);
        progress?.Report(CieProgress.WaitingForCard);
        await using var card = new CieCard(await reader.WaitForCardAsync(token).ConfigureAwait(false));
        progress?.Report(CieProgress.CardDetected);
        var cardHash = await CheckCardAsync(card, expectedCardHash, token).ConfigureAwait(false);
        progress?.Report(CieProgress.OpeningSecureChannel);
        await card.OpenSecureChannelAsync(pin, token).ConfigureAwait(false);
        progress?.Report(CieProgress.ReadingCertificate);
        var certificateBytes = await card.ReadCertificateAsync(token).ConfigureAwait(false);
        using var certificate = X509CertificateLoader.LoadCertificate(certificateBytes);
        var now = DateTime.UtcNow;
        if (now < certificate.NotBefore.ToUniversalTime() || now > certificate.NotAfter.ToUniversalTime())
            throw new CardException("Il certificato CIE è scaduto o non ancora valido.");
        progress?.Report(CieProgress.RequestingChallenge);
        var challenge = await provider.GetChallengeAsync(request, certificateBytes, token).ConfigureAwait(false);
        progress?.Report(CieProgress.Signing);
        // Android reselects the card and establishes a fresh channel before challenge signing.
        await CheckCardAsync(card, cardHash, token).ConfigureAwait(false);
        await card.OpenSecureChannelAsync(pin, token).ConfigureAwait(false);
        var digest = SHA256.HashData(challenge);
        var signature = await card.SignSha256Async(digest, token).ConfigureAwait(false);
        using var rsa = certificate.GetRSAPublicKey() ?? throw new CardException("Certificato CIE senza chiave RSA.");
        if (!rsa.VerifyHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
            throw new CardProtocolException("La firma non corrisponde al certificato della carta.");
        progress?.Report(CieProgress.Completed);
        return provider.GetCompletionUri(request, signature);
    }

    public async Task<string> AuthenticateQrAsync(CieQrAuthenticationRequest request, ReadOnlyMemory<char> pin,
        ICieQrIdentityProvider provider, IProgress<CieProgress>? progress = null, CancellationToken token = default, string? expectedCardHash = null)
    {
        ValidatePin(pin);
        progress?.Report(CieProgress.WaitingForCard);
        await using var card = new CieCard(await reader.WaitForCardAsync(token).ConfigureAwait(false));
        progress?.Report(CieProgress.CardDetected);
        var hash = await CheckCardAsync(card, expectedCardHash, token).ConfigureAwait(false);
        progress?.Report(CieProgress.OpeningSecureChannel);
        await card.OpenSecureChannelAsync(pin, token).ConfigureAwait(false);
        progress?.Report(CieProgress.ReadingCertificate);
        byte[] certificateBytes = await card.ReadCertificateAsync(token).ConfigureAwait(false);
        using var certificate = X509CertificateLoader.LoadCertificate(certificateBytes);
        var now = DateTime.UtcNow;
        if (now < certificate.NotBefore.ToUniversalTime() || now > certificate.NotAfter.ToUniversalTime())
            throw new CardException("Il certificato CIE è scaduto o non ancora valido.");
        if (new CardProfile(hash, certificateBytes, DateTimeOffset.UtcNow).GetCertificateDetails().DocumentNumber != request.DocumentNumber)
            throw new CardException("Il QR è destinato a un'altra CIE. Nessuna richiesta di accesso è stata inviata.");
        using var rsa = certificate.GetRSAPublicKey() ?? throw new CardException("Certificato CIE senza chiave RSA.");
        async Task<byte[]> Sign(ReadOnlyMemory<byte> digest, CancellationToken ct)
        {
            var signature = await card.SignSha256Async(digest, ct).ConfigureAwait(false);
            if (!rsa.VerifyHash(digest.Span, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                throw new CardProtocolException("La firma non corrisponde al certificato della CIE.");
            return signature;
        }
        progress?.Report(CieProgress.Signing);
        var qrSignature = await Sign(SHA256.HashData(Encoding.UTF8.GetBytes(request.OriginalUrl)), token).ConfigureAwait(false);
        progress?.Report(CieProgress.AuthenticatingTls);
        int tlsSignatures = 0;
        var otp = await provider.GetOtpAsync(request, certificateBytes, qrSignature, async (digest, ct) =>
        {
            if (Interlocked.Increment(ref tlsSignatures) != 1)
                throw new CardProtocolException("Il servizio ha richiesto più firme TLS del previsto.");
            var signature = await Sign(digest, ct).ConfigureAwait(false);
            progress?.Report(CieProgress.ReceivingOtp);
            return signature;
        }, token).ConfigureAwait(false);
        if (otp.Length != 4 || !otp.All(char.IsAsciiDigit)) throw new CieQrException("Codice OTP non valido.");
        progress?.Report(CieProgress.Completed);
        return otp;
    }

    private static void ValidatePin(ReadOnlyMemory<char> pin)
    {
        if (!CiePin.IsValid(pin.Span)) throw new ArgumentException("Il PIN CIE deve contenere 8 cifre.", nameof(pin));
    }

    private static async Task<string> CheckCardAsync(CieCard card, string? expected, CancellationToken token)
    {
        string id = await card.ReadServiceIdAsync(token).ConfigureAwait(false);
        string hash = Convert.ToHexString(SHA256.HashData(Convert.FromHexString(id)));
        if (expected is not null && !hash.Equals(expected, StringComparison.Ordinal))
            throw new CardException("La CIE avvicinata non è quella registrata. Il PIN salvato non è stato inviato.");
        return hash;
    }
}

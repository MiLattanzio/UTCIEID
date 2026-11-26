using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace UTCie.Sdk.Authentication;

public interface ICieIdentityProvider
{
    Task<byte[]> GetChallengeAsync(CieAuthenticationRequest request, byte[] certificate, CancellationToken token);
    Uri GetCompletionUri(CieAuthenticationRequest request, ReadOnlySpan<byte> signature);
}

/// <summary>The Android SDK X509TLS13First / X509MobileTLS13Second flow, without TLS callbacks into Android.</summary>
public sealed class CieIdentityProvider : ICieIdentityProvider, IDisposable
{
    private readonly HttpClient _http;
    private readonly CieEnvironment _environment;

    /// <param name="spkiPins">Optional, current SHA-256 SPKI pins. Standard platform certificate validation always applies.</param>
    public CieIdentityProvider(CieEnvironment environment, IReadOnlyCollection<string>? spkiPins = null)
    {
        _environment = environment;
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            AutomaticDecompression = DecompressionMethods.None
        };
        if (spkiPins is { Count: > 0 })
        {
            var pins = spkiPins.Select(p => Convert.FromBase64String(p.StartsWith("sha256/", StringComparison.Ordinal) ? p[7..] : p)).ToArray();
            if (pins.Any(p => p.Length != 32)) throw new ArgumentException("Pin SPKI non valido.", nameof(spkiPins));
            handler.ServerCertificateCustomValidationCallback = (_, cert, chain, errors) =>
                errors == SslPolicyErrors.None && cert is not null && chain is not null &&
                chain.ChainElements.Cast<X509ChainElement>().Any(e => pins.Any(pin =>
                    CryptographicOperations.FixedTimeEquals(pin, SHA256.HashData(e.Certificate.PublicKey.ExportSubjectPublicKeyInfo()))));
        }
        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20), BaseAddress = CieEndpoint.For(environment).BaseUri };
    }

    internal CieIdentityProvider(CieEnvironment environment, HttpMessageHandler handler)
    {
        _environment = environment;
        _http = new HttpClient(handler) { BaseAddress = CieEndpoint.For(environment).BaseUri, Timeout = TimeSpan.FromSeconds(20) };
    }

    public async Task<byte[]> GetChallengeAsync(CieAuthenticationRequest request, byte[] certificate, CancellationToken token)
    {
        Validate(request);
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["cert"] = Convert.ToHexString(certificate), ["authnRequest"] = request.AuthnRequest
        });
        using var message = new HttpRequestMessage(HttpMethod.Post, "Authn/X509TLS13First") { Content = content };
        using var response = await _http.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) throw new HttpRequestException("Il servizio CIE non ha accettato la richiesta.", null, response.StatusCode);
        await using var body = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
        // Sign exactly the returned bytes, preserving the Android protocol's UTF-8 challenge.
        var buffer = new byte[16385];
        int length = 0, read;
        do { read = await body.ReadAsync(buffer.AsMemory(length), token).ConfigureAwait(false); length += read; }
        while (read > 0 && length < buffer.Length);
        if (length is 0 or > 16384) throw new HttpRequestException("Challenge CIE vuota o troppo grande.");
        return buffer[..length];
    }

    public Uri GetCompletionUri(CieAuthenticationRequest request, ReadOnlySpan<byte> signature)
    {
        Validate(request);
        if (signature.Length is < 128 or > 512) throw new ArgumentException("Firma CIE non valida.");
        return new Uri(CieEndpoint.For(_environment).BaseUri, "Authn/X509MobileTLS13Second?challenge=" +
            Convert.ToHexString(signature) + "&" + Uri.EscapeDataString(request.Name) + "=" + Uri.EscapeDataString(request.Value));
    }

    private void Validate(CieAuthenticationRequest request)
    {
        if (request.Environment != _environment) throw new ArgumentException("Ambiente della richiesta CIE non corrispondente.");
    }
    public void Dispose() => _http.Dispose();
}

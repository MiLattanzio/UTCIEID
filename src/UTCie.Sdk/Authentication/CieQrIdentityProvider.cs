using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using BcCertificate = Org.BouncyCastle.Tls.Certificate;
using BcCertificateRequest = Org.BouncyCastle.Tls.CertificateRequest;

namespace UTCie.Sdk.Authentication;

public delegate Task<byte[]> CieTlsSignAsync(ReadOnlyMemory<byte> digest, CancellationToken token);

public interface ICieQrIdentityProvider
{
    Task<string> GetOtpAsync(CieQrAuthenticationRequest request, byte[] certificate, byte[] qrSignature,
        CieTlsSignAsync signTls, CancellationToken token);
}

/// <summary>QR hybrid protocol: form POST over TLS 1.2 with the card as client certificate.</summary>
public sealed class CieQrIdentityProvider : ICieQrIdentityProvider
{
    public async Task<string> GetOtpAsync(CieQrAuthenticationRequest request, byte[] certificate, byte[] qrSignature,
        CieTlsSignAsync signTls, CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(40));
        var ct = timeout.Token;
        var host = GetTlsHost(request.Environment);
        using var tcp = new TcpClient();
        using var cancel = ct.Register(tcp.Dispose);
        try
        {
            await tcp.ConnectAsync(host, 443, ct).ConfigureAwait(false);
            var body = BuildForm(request, qrSignature);
            return await Task.Run(() =>
            {
                var protocol = new TlsClientProtocol(tcp.GetStream());
                var client = new CardTlsClient(host, certificate, signTls, ct);
                protocol.Connect(client);
                using var tlsStream = protocol.Stream;
                if (!client.ClientAuthenticated) throw new CieQrException("Il servizio non ha richiesto l'autenticazione TLS della CIE.");
                ct.ThrowIfCancellationRequested();
                byte[] header = Encoding.ASCII.GetBytes("POST /idp/Authn/SSL/X509AuthIbrido HTTP/1.1\r\nHost: " + host +
                    "\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept: text/plain\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: " + body.Length + "\r\n\r\n");
                protocol.Stream.Write(header);
                protocol.Stream.Write(body);
                protocol.Stream.Flush();
                return ParseOtp(CieQrHttp.ReadResponse(protocol.Stream));
            }, ct).ConfigureAwait(false);
        }
        catch (Exception) when (ct.IsCancellationRequested)
        {
            token.ThrowIfCancellationRequested();
            throw new TimeoutException("Il servizio CIE non ha risposto in tempo.");
        }
        catch (TlsFatalAlert e) { throw new CieQrException("Autenticazione TLS della CIE non riuscita (alert " + e.AlertDescription + ").", e); }
        catch (IOException e) { throw new CieQrException("Connessione al servizio CIE interrotta.", e); }
        catch (SocketException e) { throw new CieQrException("Impossibile raggiungere il servizio CIE.", e); }
    }

    // Production /SSL/ routes on the public IdP now redirect to this dedicated
    // certificate-authentication host. It is fixed here, never supplied by a QR.
    internal static string GetTlsHost(CieEnvironment environment) => environment == CieEnvironment.Production
        ? "mtls.idserver.servizicie.interno.gov.it"
        : CieEndpoint.For(environment).BaseUri.IdnHost;

    internal static byte[] BuildForm(CieQrAuthenticationRequest request, byte[] signature)
    {
        if (signature.Length is < 128 or > 512) throw new ArgumentException("Firma CIE non valida.");
        return Encoding.ASCII.GetBytes("hashJsonFirmato=" + Convert.ToHexString(signature) + "&opId=" + Uri.EscapeDataString(request.OperationId));
    }

    internal static string ParseOtp(string body)
    {
        // The official client expects a colon followed by exactly four ASCII digits.
        // Accept only success labels; never display a numeric error as an OTP.
        int colon = body.IndexOf(':');
        if (colon > 0 && body.Length == colon + 5 && body[(colon + 1)..].All(char.IsAsciiDigit) &&
            body[..colon] is "otp" or "OTP" or "codice" or "OK")
            return body[(colon + 1)..];
        throw new CieQrException("Il servizio CIE non ha restituito un OTP valido. La richiesta potrebbe essere scaduta: avvia un nuovo accesso.");
    }

    internal sealed class CardTlsClient(string host, byte[] certificate, CieTlsSignAsync sign, CancellationToken token,
        X509Certificate2? testTrustRoot = null) : DefaultTlsClient(new BcTlsCrypto(new SecureRandom()))
    {
        public bool ClientAuthenticated { get; private set; }
        protected override ProtocolVersion[] GetSupportedVersions() => [ProtocolVersion.TLSv12];
        protected override int[] GetSupportedCipherSuites() =>
            [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
             CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384];
        protected override IList<ServerName> GetSniServerNames() => [new ServerName(NameType.host_name, Encoding.ASCII.GetBytes(host))];
        public override TlsAuthentication GetAuthentication() => new CardAuthentication(this, host, certificate, sign, token, testTrustRoot);

        private sealed class CardAuthentication(CardTlsClient owner, string host, byte[] certificate, CieTlsSignAsync sign,
            CancellationToken token, X509Certificate2? testTrustRoot) : TlsAuthentication
        {
            private bool _serverTrusted;
            public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
            {
                token.ThrowIfCancellationRequested();
                var chainBytes = serverCertificate.Certificate.GetCertificateList();
                if (chainBytes.Length is < 1 or > 10) throw new TlsFatalAlert(AlertDescription.bad_certificate);
                using var leaf = X509CertificateLoader.LoadCertificate(chainBytes[0].GetEncoded());
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.DisableCertificateDownloads = true;
                chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
                var extras = new List<X509Certificate2>();
                try
                {
                    for (int i = 1; i < chainBytes.Length; i++)
                    {
                        var cert = X509CertificateLoader.LoadCertificate(chainBytes[i].GetEncoded());
                        extras.Add(cert); chain.ChainPolicy.ExtraStore.Add(cert);
                    }
                    if (testTrustRoot is not null)
                    {
                        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                        chain.ChainPolicy.CustomTrustStore.Add(testTrustRoot);
                    }
                    if (!leaf.MatchesHostname(host, allowWildcards: true, allowCommonName: false) || !chain.Build(leaf))
                        throw new TlsFatalAlert(AlertDescription.bad_certificate);
                    _serverTrusted = true;
                }
                finally { foreach (var cert in extras) cert.Dispose(); }
            }

            public TlsCredentials GetClientCredentials(BcCertificateRequest request)
            {
                token.ThrowIfCancellationRequested();
                var algorithm = new SignatureAndHashAlgorithm(Org.BouncyCastle.Tls.HashAlgorithm.sha256, SignatureAlgorithm.rsa);
                if (!_serverTrusted || !request.CertificateTypes.Contains(ClientCertificateType.rsa_sign) ||
                    request.SupportedSignatureAlgorithms is null || !request.SupportedSignatureAlgorithms.Contains(algorithm))
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                return new CardSigner(new BcCertificate([owner.Crypto.CreateCertificate(certificate)]), algorithm, hash =>
                {
                    if (owner.ClientAuthenticated || hash.Length != 32) throw new TlsFatalAlert(AlertDescription.internal_error);
                    token.ThrowIfCancellationRequested();
                    byte[] signature = sign(hash, token).GetAwaiter().GetResult();
                    using var cert = X509CertificateLoader.LoadCertificate(certificate);
                    using var rsa = cert.GetRSAPublicKey();
                    if (rsa is null || !rsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                        throw new TlsFatalAlert(AlertDescription.decrypt_error);
                    owner.ClientAuthenticated = true;
                    return signature;
                });
            }
        }
    }

    private sealed class CardSigner(BcCertificate certificate, SignatureAndHashAlgorithm algorithm, Func<byte[], byte[]> sign) : TlsCredentialedSigner
    {
        public BcCertificate Certificate => certificate;
        public SignatureAndHashAlgorithm SignatureAndHashAlgorithm => algorithm;
        public byte[] GenerateRawSignature(byte[] hash) => sign(hash);
        public TlsStreamSigner GetStreamSigner() => null!;
    }
}

public sealed class CieQrException(string message, Exception? inner = null) : Exception(message, inner);

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NUnit.Framework;
using Org.BouncyCastle.Tls;
using UTCIEID.App;
using UTCie.Sdk;
using UTCie.Sdk.Authentication;
using UTCie.Sdk.Card;
using ZXing;
using ZXing.QrCode;
using SkiaSharp;
using System.Runtime.InteropServices;

namespace UTCie.Tests;

public class QrAuthenticationTests
{
    internal const string Qr = "https://idserver.servizicie.interno.gov.it/idp/erroreQr.jsp?opId=_AUTH-synthetic&opType=login&SPName=http%3A%2F%2Fwww.inps.it&IdPName=https%3A%2F%2Fidserver.servizicie.interno.gov.it%2Fidp%2F&userId=CA12345AA&opText=Accedi%20a+INPS";
    private static CieQrAuthenticationRequest Request(string? url = null) => CieQrAuthenticationRequest.Parse(url ?? Qr, CieEnvironment.Production);

    [Test] public void ProductionQrUsesTheDedicatedOfficialCertificateEndpoint()
    {
        Assert.That(CieQrIdentityProvider.GetTlsHost(Request().Environment), Is.EqualTo("mtls.idserver.servizicie.interno.gov.it"));
        Assert.That(Request().OriginalUrl, Does.StartWith("https://idserver.servizicie.interno.gov.it/"));
    }

    [Test] public void ExactOriginalQrIsPreservedForSigning()
    {
        var request = Request();
        Assert.That(request.OriginalUrl, Is.EqualTo(Qr));
        Assert.That(request.ServiceName, Is.EqualTo("www.inps.it"));
        Assert.That(request.OperationId, Is.EqualTo("_AUTH-synthetic"));
        Assert.That(request.ToString(), Does.Not.Contain(request.DocumentNumber));
        var form = Encoding.ASCII.GetString(CieQrIdentityProvider.BuildForm(request, new byte[256]));
        Assert.That(form, Is.EqualTo("hashJsonFirmato=" + new string('0', 512) + "&opId=_AUTH-synthetic"));
    }

    [Test] public void OfficialQrLiteralSpacesArePreservedForSigning()
    {
        string link = Qr.Replace("Accedi%20a+INPS", "Accesso al servizio - http://www.inps.it");
        Assert.That(Request(link).OriginalUrl, Is.EqualTo(link));
        Assert.That(Request(link).ServiceName, Is.EqualTo("www.inps.it"));
        Assert.Throws<ArgumentException>(() => Request(link.Replace("servizio -", "servizio\u00a0-")));
        Assert.Throws<ArgumentException>(() => Request(link.Replace("/idp/erroreQr.jsp", "/idp/errore Qr.jsp")));
    }

    [TestCase("https://idserver.servizicie.interno.gov.it", "https://attacker.example")]
    [TestCase("https://idserver.servizicie.interno.gov.it", "https://idserver.servizicie.interno.gov.it.attacker.example")]
    [TestCase("https://idserver.servizicie.interno.gov.it", "https://user@idserver.servizicie.interno.gov.it")]
    [TestCase("https://idserver.servizicie.interno.gov.it", "https://idserver.servizicie.interno.gov.it:444")]
    [TestCase("https://idserver.servizicie.interno.gov.it", "http://idserver.servizicie.interno.gov.it")]
    [TestCase("opType=login", "opType=changePin")]
    [TestCase("CA12345AA", "bad")]
    [TestCase("IdPName=https%3A%2F%2Fidserver.servizicie.interno.gov.it%2Fidp%2F", "IdPName=https%3A%2F%2Fattacker.example%2Fidp%2F")]
    [TestCase("opText=Accedi%20a+INPS", "opText=%0A")]
    public void InvalidQrRejected(string before, string after) => Assert.Throws<ArgumentException>(() => Request(Qr.Replace(before, after)));

    [TestCase("&opId=another")]
    [TestCase("&%6fpId=another")]
    [TestCase("#fragment")]
    [TestCase(" ")]
    [TestCase("&extra=%xx")]
    public void AmbiguousQrRejected(string suffix) => Assert.Throws<ArgumentException>(() => Request(Qr + suffix));

    [TestCase("otp:0123", "0123")]
    [TestCase("codice:1234", "1234")]
    public void OtpPreservesLeadingZero(string response, string expected) => Assert.That(CieQrIdentityProvider.ParseOtp(response), Is.EqualTo(expected));

    [TestCase("")]
    [TestCase("error:1234")]
    [TestCase("otp:12345")]
    [TestCase("otp:１２３４")]
    [TestCase("otp:1234\n")]
    [TestCase("<html>otp:1234</html>")]
    public void InvalidOtpRejected(string response) => Assert.Throws<CieQrException>(() => CieQrIdentityProvider.ParseOtp(response));

    [TestCase("Content-Length: 8\r\n", "otp:0123")]
    [TestCase("Transfer-Encoding: chunked\r\n", "4\r\notp:\r\n4\r\n0123\r\n0\r\n\r\n")]
    public void HttpLengthAndChunkedBodies(string headers, string body)
    {
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\n" + headers + "\r\n" + body));
        Assert.That(CieQrHttp.ReadResponse(stream), Is.EqualTo("otp:0123"));
    }

    [TestCase("HTTP/1.1 302 Found\r\nLocation: https://attacker.example\r\n\r\n")]
    [TestCase("HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n")]
    [TestCase("HTTP/1.1 200 OK\r\nContent-Length: 8\r\nTransfer-Encoding: chunked\r\n\r\n")]
    [TestCase("HTTP/1.1 200 OK\r\nContent-Length: 8\r\nContent-Length: 8\r\n\r\n")]
    [TestCase("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n")]
    public void HttpRejectsRedirectsAndAmbiguousFraming(string response)
    {
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes(response));
        Assert.Throws<CieQrException>(() => CieQrHttp.ReadResponse(stream));
    }

    [Test] public void DecodesARealQrImageToTheExactPayload()
    {
        var writer = new BarcodeWriterPixelData { Format = BarcodeFormat.QR_CODE, Options = new QrCodeEncodingOptions { Width = 500, Height = 500, Margin = 4 } };
        var image = writer.Write(Qr);
        Assert.That(CieQrDecoder.DecodeBgra(image.Pixels, image.Width, image.Height), Is.EqualTo(Qr));
        Assert.Throws<ArgumentException>(() => CieQrDecoder.DecodeBgra(new byte[400], 10, 10));
        Assert.Throws<ArgumentException>(() => CieQrDecoder.DecodeBgra([], 9999, 9999));
    }

    [TestCase(SKEncodedImageFormat.Png)]
    [TestCase(SKEncodedImageFormat.Jpeg)]
    public async Task ReadsEncodedQrImageWithoutStartingAvalonia(SKEncodedImageFormat format)
    {
        var image = new BarcodeWriterPixelData { Format = BarcodeFormat.QR_CODE,
            Options = new QrCodeEncodingOptions { Width = 500, Height = 500, Margin = 4 } }.Write(Qr);
        using var bitmap = new SKBitmap(new SKImageInfo(image.Width, image.Height, SKColorType.Bgra8888, SKAlphaType.Opaque));
        Marshal.Copy(image.Pixels, 0, bitmap.GetPixels(), image.Pixels.Length);
        using var encoded = bitmap.Encode(format, 100);
        using var stream = encoded.AsStream();
        Assert.That(await QrImageReader.ReadAsync(stream), Is.EqualTo(Qr));
    }

    [Test] public async Task CardSignsQrAndTlsWithOnePinVerification()
    {
        var simulator = new SimulatedCie();
        var provider = new VerifyingQrProvider();
        var otp = await new CieClient(new FakeReader(simulator)).AuthenticateQrAsync(Request(), "12345678".AsMemory(), provider);
        Assert.That(otp, Is.EqualTo("0123"));
        Assert.That(provider.Calls, Is.EqualTo(1));
        Assert.That(simulator.PinVerifications, Is.EqualTo(1));
        Assert.That(simulator.Disposed, Is.True);
    }

    [Test] public void QrForAnotherDocumentNeverContactsProvider()
    {
        var simulator = new SimulatedCie();
        var provider = new VerifyingQrProvider();
        Assert.ThrowsAsync<CardException>(async () => await new CieClient(new FakeReader(simulator)).AuthenticateQrAsync(
            Request(Qr.Replace("CA12345AA", "CA12345AB")), "12345678".AsMemory(), provider));
        Assert.That(provider.Calls, Is.Zero);
    }

    [Test] public void RepeatedTlsSignatureIsRejected()
    {
        var simulator = new SimulatedCie();
        Assert.ThrowsAsync<CardProtocolException>(async () => await new CieClient(new FakeReader(simulator)).AuthenticateQrAsync(
            Request(), "12345678".AsMemory(), new VerifyingQrProvider(repeat: true)));
        Assert.That(simulator.PinVerifications, Is.EqualTo(1));
    }

    [Test] public void QrWrongPinIsNeverRetried()
    {
        var simulator = new SimulatedCie();
        var provider = new VerifyingQrProvider();
        Assert.ThrowsAsync<PinException>(async () => await new CieClient(new FakeReader(simulator)).AuthenticateQrAsync(
            Request(), "00000000".AsMemory(), provider));
        Assert.That(simulator.PinVerifications, Is.EqualTo(1));
        Assert.That(provider.Calls, Is.Zero);
    }

    [Test] public void QrRegisteredCardMismatchNeverSendsPin()
    {
        var simulator = new SimulatedCie();
        Assert.ThrowsAsync<CardException>(async () => await new CieClient(new FakeReader(simulator)).AuthenticateQrAsync(
            Request(), "12345678".AsMemory(), new VerifyingQrProvider(), expectedCardHash: new string('0', 64)));
        Assert.That(simulator.PinVerifications, Is.Zero);
    }

    [TestCase(true)] [TestCase(false)]
    public async Task UiShowsOtpWithoutBrowserCompletionAndClearsIt(bool background)
    {
        var model = new MainViewModel(new FakeReader(new SimulatedCie()), Qr, qrProvider: new VerifyingQrProvider());
        await model.RefreshAsync(); model.Pin = "12345678";
        model.ContinueCommand.Execute(null);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        while (model.Busy) await Task.Delay(5, timeout.Token);
        Assert.That(model.Error, Is.False, model.Detail);
        Assert.That(model.Otp, Is.EqualTo("0123"));
        Assert.That(model.HasCompletion, Is.False);
        if (background) model.OnDeactivated();
        else model.RequestLink = Qr.Replace("_AUTH-synthetic", "_AUTH-another");
        Assert.That(model.HasOtp, Is.False);
    }

    [TestCase(true, "localhost", false, true)]
    [TestCase(false, "localhost", false, false)]
    [TestCase(true, "wrong.example", false, false)]
    [TestCase(true, "localhost", true, false)]
    public async Task TlsAuthenticatesWithExternalCardSignerAndChecksServer(bool trust, string host, bool expired, bool expectedSuccess)
    {
        using var serverKey = RSA.Create(2048);
        var serverRequest = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=localhost", serverKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("localhost");
        serverRequest.CertificateExtensions.Add(san.Build());
        serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
        using var serverCert = serverRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-2), DateTimeOffset.UtcNow.AddHours(expired ? -1 : 1));
        using var cardKey = RSA.Create(2048);
        var cardRequest = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=SYNTHETIC CARD", cardKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cardCert = cardRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddHours(1));
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        int signatures = 0; bool clientCertificateSeen = false;
        var server = Task.Run(async () =>
        {
            using var socket = await listener.AcceptTcpClientAsync(timeout.Token);
            using var tls = new SslStream(socket.GetStream(), false, (_, cert, _, _) =>
            {
                clientCertificateSeen = cert is not null && cert.GetRawCertData().AsSpan().SequenceEqual(cardCert.RawData);
                return clientCertificateSeen;
            });
            try
            {
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = serverCert, ClientCertificateRequired = true, EnabledSslProtocols = SslProtocols.Tls12,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, timeout.Token);
                await tls.WriteAsync("TLS OK"u8.ToArray(), timeout.Token);
            }
            catch (Exception) when (!expectedSuccess) { }
        });
        using var clientSocket = new TcpClient();
        await clientSocket.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, timeout.Token);
        using var cancellation = timeout.Token.Register(clientSocket.Dispose);
        var client = new CieQrIdentityProvider.CardTlsClient(host, cardCert.RawData, (hash, _) =>
        {
            signatures++;
            return Task.FromResult(cardKey.SignHash(hash.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }, timeout.Token, trust ? serverCert : null);
        var handshake = Task.Run(() =>
        {
            var tls = new TlsClientProtocol(clientSocket.GetStream());
            tls.Connect(client);
            using var stream = tls.Stream;
            byte[] bytes = new byte[6]; stream.ReadExactly(bytes);
            return Encoding.ASCII.GetString(bytes);
        });
        if (expectedSuccess) Assert.That(await handshake, Is.EqualTo("TLS OK"));
        else Assert.ThrowsAsync<TlsFatalAlert>(async () => await handshake);
        await server;
        Assert.That(signatures, Is.EqualTo(expectedSuccess ? 1 : 0));
        Assert.That(clientCertificateSeen, Is.EqualTo(expectedSuccess));
    }

    private sealed class VerifyingQrProvider(bool repeat = false) : ICieQrIdentityProvider
    {
        public int Calls { get; private set; }
        public async Task<string> GetOtpAsync(CieQrAuthenticationRequest request, byte[] certificate, byte[] qrSignature, CieTlsSignAsync signer, CancellationToken token)
        {
            Calls++;
            using var cert = X509CertificateLoader.LoadCertificate(certificate);
            using var key = cert.GetRSAPublicKey()!;
            Assert.That(key.VerifyData(Encoding.UTF8.GetBytes(Qr), qrSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), Is.True);
            var tlsHash = SHA256.HashData("synthetic TLS transcript"u8);
            Assert.That(key.VerifyHash(tlsHash, await signer(tlsHash, token), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), Is.True);
            if (repeat) await signer(tlsHash, token);
            return "0123";
        }
    }
}

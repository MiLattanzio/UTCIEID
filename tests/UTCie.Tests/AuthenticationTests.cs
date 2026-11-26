using System.Net;
using NUnit.Framework;
using UTCie.Sdk.Authentication;

namespace UTCie.Tests;

public class AuthenticationTests
{
    private const string Root = "https://idserver.servizicie.interno.gov.it/idp/OpenApp";
    private const string Query = "?authnRequestString=a%2Bb%3D&name=state&value=x%26y%3Dz";
    [TestCase("/idp/erroreQr.jsp", "OTP")]
    [TestCase("/idp/login/livello2QR", "livello 2")]
    public void OfficialQrNeedsItsOwnProtocol(string path, string message)
    {
        var error = Assert.Throws<CieUnsupportedFlowException>(() => CieAuthenticationRequest.Parse(
            "https://idserver.servizicie.interno.gov.it" + path + "?opId=synthetic&opType=login", CieEnvironment.Production));
        Assert.That(error!.Message, Does.Contain(message));
    }
    [TestCase("https://attacker.example/idp/erroreQr.jsp")]
    [TestCase("http://idserver.servizicie.interno.gov.it/idp/erroreQr.jsp")]
    [TestCase("https://preproduzione.idserver.servizicie.interno.gov.it/idp/erroreQr.jsp")]
    public void QrRecognitionDoesNotRelaxOriginValidation(string link) =>
        Assert.Throws<ArgumentException>(() => CieAuthenticationRequest.Parse(link, CieEnvironment.Production));
    [Test] public void DecodeExactlyOnce()
    {
        var request = CieAuthenticationRequest.Parse(Root + Query, CieEnvironment.Production);
        Assert.That(request.AuthnRequest, Is.EqualTo("a+b="));
        Assert.That(request.Value, Is.EqualTo("x&y=z"));
        using var provider = new CieIdentityProvider(CieEnvironment.Production);
        var final = provider.GetCompletionUri(request, new byte[256]);
        Assert.That(final.Query, Does.EndWith("&state=x%26y%3Dz"));
    }
    [TestCase("https://attacker.example/idp/OpenApp")]
    [TestCase("http://idserver.servizicie.interno.gov.it/idp/OpenApp")]
    [TestCase("https://idserver.servizicie.interno.gov.it.attacker.example/idp/OpenApp")]
    [TestCase("https://idserver.servizicie.interno.gov.it:444/idp/OpenApp")]
    [TestCase("https://user@idserver.servizicie.interno.gov.it/idp/OpenApp")]
    [TestCase("https://idserver.servizicie.interno.gov.it/OpenApp")]
    [TestCase("file:///idp/OpenApp")]
    public void UntrustedOriginsRejected(string origin) =>
        Assert.Throws<ArgumentException>(() => CieAuthenticationRequest.Parse(origin + Query, CieEnvironment.Production));
    [TestCase("&name=other")]
    [TestCase("&OpText=%0A")]
    [TestCase("&imgUrl=%xx")]
    public void AmbiguousQueryRejected(string extra) =>
        Assert.Throws<ArgumentException>(() => CieAuthenticationRequest.Parse(Root + Query + extra, CieEnvironment.Production));
    [Test] public async Task HttpSendsEncodedFormAndPreservesChallengeBytes()
    {
        var handler = new RecordingHandler(new(HttpStatusCode.OK) { Content = new ByteArrayContent([0x41, 0x0a, 0xc3, 0xa8]) });
        using var provider = new CieIdentityProvider(CieEnvironment.Production, handler);
        var request = CieAuthenticationRequest.Parse(Root + Query, CieEnvironment.Production);
        Assert.That(await provider.GetChallengeAsync(request, [1, 0xff], CancellationToken.None), Is.EqualTo(new byte[] { 0x41, 0x0a, 0xc3, 0xa8 }));
        Assert.That(handler.Uri!.AbsolutePath, Is.EqualTo("/idp/Authn/X509TLS13First"));
        Assert.That(handler.Body, Is.EqualTo("cert=01FF&authnRequest=a%2Bb%3D"));
    }
    [TestCase(0)] [TestCase(16385)]
    public void InvalidChallengeLengthRejected(int size)
    {
        using var provider = new CieIdentityProvider(CieEnvironment.Production, new RecordingHandler(new(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[size]) }));
        Assert.ThrowsAsync<HttpRequestException>(async () => await provider.GetChallengeAsync(CieAuthenticationRequest.Parse(Root + Query, CieEnvironment.Production), [], CancellationToken.None));
    }
    [Test] public void HttpRedirectDoesNotBecomeChallenge()
    {
        using var provider = new CieIdentityProvider(CieEnvironment.Production, new RecordingHandler(new(HttpStatusCode.Redirect) { Content = new StringContent("redirect") }));
        Assert.ThrowsAsync<HttpRequestException>(async () => await provider.GetChallengeAsync(CieAuthenticationRequest.Parse(Root + Query, CieEnvironment.Production), [], CancellationToken.None));
    }
    [Test] public void WrongEnvironmentRejectedBeforeNetwork()
    {
        using var provider = new CieIdentityProvider(CieEnvironment.Collaudo, new RecordingHandler(new(HttpStatusCode.OK)));
        Assert.ThrowsAsync<ArgumentException>(async () => await provider.GetChallengeAsync(CieAuthenticationRequest.Parse(Root + Query, CieEnvironment.Production), [], CancellationToken.None));
    }

    private sealed class RecordingHandler(HttpResponseMessage response) : HttpMessageHandler
    {
        public Uri? Uri { get; private set; }
        public string? Body { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Uri = request.RequestUri;
            Body = await request.Content!.ReadAsStringAsync(token);
            return response;
        }
    }
}

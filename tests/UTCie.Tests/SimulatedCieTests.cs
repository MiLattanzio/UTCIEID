using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using UTCie.Sdk;
using UTCie.Sdk.Authentication;
using UTCie.Sdk.Card;
using UTCie.Sdk.Crypto;

namespace UTCie.Tests;

public class SimulatedCieTests
{
    [TestCase(false)]
    [TestCase(true)]
    public async Task CertificateReadsAcceptAuthenticatedOuterEndOfFile(bool separateEof)
    {
        var simulator = new SimulatedCie { EchoReadStatus = true, SeparateEndOfFile = separateEof };
        var cert = await new CieClient(new FakeReader(simulator)).ReadCertificateAsync("12345678".AsMemory());
        Assert.That(cert.Subject, Is.EqualTo("TEST CARD"));
        Assert.That(simulator.PinVerifications, Is.EqualTo(1));
    }

    [Test] public async Task DiagnosticChannelNeverVerifiesPinOrEnablesCertificateRead()
    {
        var simulator = new SimulatedCie();
        await using var card = new CieCard(simulator);
        await card.ProbeSecureChannelAsync();
        Assert.That(simulator.PinVerifications, Is.Zero);
        Assert.That(simulator.ExternalProofsVerified, Is.EqualTo(1));
        Assert.ThrowsAsync<InvalidOperationException>(async () => await card.ReadCertificateAsync());
    }

    [Test] public async Task FullChannelCertificateAndChallengeSignature()
    {
        var simulator = new SimulatedCie();
        var client = new CieClient(new FakeReader(simulator));
        var request = CieAuthenticationRequest.Parse("https://idserver.servizicie.interno.gov.it/idp/OpenApp?authnRequestString=test&name=state&value=123", CieEnvironment.Production);
        var uri = await client.AuthenticateAsync(request, "12345678".AsMemory(), new FakeProvider());
        Assert.That(uri.Host, Is.EqualTo("idserver.servizicie.interno.gov.it"));
        Assert.That(simulator.PinVerifications, Is.EqualTo(2));
        Assert.That(simulator.ExternalProofsVerified, Is.EqualTo(2));
        Assert.That(simulator.Disposed, Is.True);
        Assert.That(simulator.CorrectedReads, Is.GreaterThan(0));
    }
    [Test] public async Task RegisteredCardMismatchDoesNotAttemptPin()
    {
        var simulator = new SimulatedCie();
        var client = new CieClient(new FakeReader(simulator));
        Assert.ThrowsAsync<CardException>(async () => await client.ReadCertificateAsync("12345678".AsMemory(), expectedCardHash: new string('0', 64)));
        Assert.That(simulator.PinVerifications, Is.Zero);
        Assert.That(simulator.Disposed, Is.True);
        await Task.CompletedTask;
    }
    [Test] public void IncorrectPinIsNeverRetried()
    {
        var simulator = new SimulatedCie();
        var client = new CieClient(new FakeReader(simulator));
        var error = Assert.ThrowsAsync<PinException>(async () => await client.ReadCertificateAsync("11111111".AsMemory()));
        Assert.That(error!.RemainingAttempts, Is.EqualTo(2));
        Assert.That(simulator.PinVerifications, Is.EqualTo(1));
        Assert.That(simulator.Disposed, Is.True);
    }
    [Test] public void ModifiedCardProofFailsBeforePin()
    {
        var simulator = new SimulatedCie { CorruptInternalProof = true };
        var client = new CieClient(new FakeReader(simulator));
        Assert.ThrowsAsync<CardProtocolException>(async () => await client.ReadCertificateAsync("12345678".AsMemory()));
        Assert.That(simulator.PinVerifications, Is.Zero);
        Assert.That(simulator.Disposed, Is.True);
    }
    [Test] public void ForgedResponseMacFailsBeforePin()
    {
        var simulator = new SimulatedCie { CorruptMac = true };
        var client = new CieClient(new FakeReader(simulator));
        Assert.ThrowsAsync<CardProtocolException>(async () => await client.ReadCertificateAsync("12345678".AsMemory()));
        Assert.That(simulator.PinVerifications, Is.Zero);
    }

    private sealed class FakeProvider : ICieIdentityProvider
    {
        public Task<byte[]> GetChallengeAsync(CieAuthenticationRequest request, byte[] certificate, CancellationToken token)
        {
            using var cert = X509CertificateLoader.LoadCertificate(certificate);
            Assert.That(cert.Subject, Does.Contain("TEST CARD"));
            return Task.FromResult("test-challenge\n"u8.ToArray());
        }
        public Uri GetCompletionUri(CieAuthenticationRequest request, ReadOnlySpan<byte> signature) =>
            new("https://idserver.servizicie.interno.gov.it/idp/Authn/X509MobileTLS13Second?challenge=" + Convert.ToHexString(signature));
    }
}

internal sealed class FakeReader(ICardTransport transport) : ICardReader
{
    public Task<ReaderStatus> GetStatusAsync(CancellationToken cancellationToken = default) => Task.FromResult(new ReaderStatus(true, true, "Ready"));
    public Task<ICardTransport> WaitForCardAsync(CancellationToken cancellationToken = default) { cancellationToken.ThrowIfCancellationRequested(); return Task.FromResult(transport); }
}

/// <summary>In-memory card peer. Verifies terminal proof, command MACs and PIN; generates real RSA certificate/signature.
/// It exercises sequencing, not the card vendor's authority-certificate trust policy.</summary>
internal sealed class SimulatedCie : ICardTransport
{
    private readonly RSA _rsa = RSA.Create(2048);
    private readonly byte[] _p, _q, _g, _publicKey, _certificate;
    private readonly byte[] _challenge = Convert.FromHexString("1122334455667788");
    private byte[] _terminalDh = [], _cardDh = [], _enc = [], _mac = [], _counter = [], _chain = [];
    private byte[]? _nextCounter;
    private ushort _selectedFile;
    private bool _signing;
    public int PinVerifications { get; private set; }
    public int ExternalProofsVerified { get; private set; }
    public int CorrectedReads { get; private set; }
    public bool Disposed { get; private set; }
    public bool CorruptInternalProof { get; init; }
    public bool CorruptMac { get; init; }
    public bool EchoReadStatus { get; init; }
    public bool SeparateEndOfFile { get; init; }

    public SimulatedCie()
    {
        using var dsa = DSA.Create(1024);
        var group = dsa.ExportParameters(false);
        _p = group.P!; _q = group.Q!; _g = group.G!;
        var pub = _rsa.ExportParameters(false);
        _publicKey = BerTlv.Encode(0x30, [..BerTlv.Encode(2, [0, ..pub.Modulus!]), ..BerTlv.Encode(2, pub.Exponent!)]);
        var request = new CertificateRequest("CN=TEST CARD, SERIALNUMBER=IDCIT-CA12345AA", _rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        _certificate = certificate.Export(X509ContentType.Cert);
    }

    public ValueTask<byte[]> TransceiveAsync(ReadOnlyMemory<byte> bytes, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var command = ApduCommand.Parse(bytes.Span);
        bool secure = (command.Cla & 12) == 12;
        if (secure) command = Unprotect(command);
        _chain = [.._chain, ..command.Data];
        ApduResponse response;
        if ((command.Cla & 16) != 0) response = new([], 0x9000);
        else
        {
            command = command with { Data = _chain };
            _chain = [];
            response = Execute(command, secure);
        }
        byte[] result = secure ? Protect(response) : [..response.Data, (byte)(response.Status >> 8), (byte)response.Status];
        if (secure && EchoReadStatus && command.Ins == 0xb0 && response.Status is 0x6282 or 0x6b00)
        { result[^2] = (byte)(response.Status >> 8); result[^1] = (byte)response.Status; }
        if (_nextCounter is not null) { _counter = _nextCounter; _nextCounter = null; }
        return ValueTask.FromResult(result);
    }

    private ApduResponse Execute(ApduCommand command, bool secure)
    {
        byte[] data = [];
        switch (command.Ins)
        {
            case 0xa4:
                if (command.P1 == 2) _selectedFile = (ushort)((command.Data[0] << 8) | command.Data[1]);
                break;
            case 0xb0:
                byte[] file = _selectedFile switch { 0x1001 => new byte[12], 0x1004 => _publicKey, 0x1003 => _certificate, _ => throw new InvalidOperationException() };
                int offset = command.P1 * 256 + command.P2;
                int remaining = file.Length - offset;
                if (remaining == 0) return new([], 0x6b00);
                if (remaining < command.Le!.Value && command.Le == 256)
                { CorrectedReads++; return new([], (ushort)(0x6c00 | remaining)); }
                int size = Math.Min(remaining, command.Le!.Value);
                return new(file.AsSpan(offset, size).ToArray(), (ushort)(size == remaining && _selectedFile != 0x1001 && !SeparateEndOfFile ? 0x6282 : 0x9000));
            case 0xcb:
                if (command.Data.Length == 12)
                {
                    int tag = command.Data[^2];
                    byte[] value = tag switch { 0x97 => _g, 0x98 => _p, 0x99 => _q, _ => throw new InvalidOperationException() };
                    data = BerTlv.Encode(0x70, BerTlv.Encode(0xbfa101, BerTlv.Encode(0xa3, BerTlv.Encode(tag, value))));
                }
                else if (command.Data.Length == 11)
                    data = BerTlv.Encode(0x70, BerTlv.Encode(0xbfa004, BerTlv.Encode(0x7f49,
                        [..BerTlv.Encode(0x81, IasConstants.TerminalModulus), ..BerTlv.Encode(0x82, [1, 0, 1]),
                         ..BerTlv.Encode(0x5f20, new byte[12]), ..BerTlv.Encode(0x5f4c, new byte[7])])));
                else data = BerTlv.Encode(0xa6, BerTlv.Encode(0x91, _cardDh));
                break;
            case 0x22:
                if (!secure && command.P2 == 0xa6)
                {
                    _terminalDh = BerTlv.ParseMany(command.Data).Single(x => x.Tag == 0x91).Value;
                    byte[] exponent = [0x12, 0x34, 0x56, 0x78];
                    _cardDh = CardCrypto.ModPow(_g, exponent, _p);
                    var shared = CardCrypto.ModPow(_terminalDh, exponent, _p);
                    _enc = SHA256.HashData([..shared, 0, 0, 0, 1])[..16];
                    _mac = SHA256.HashData([..shared, 0, 0, 0, 2])[..16];
                    _counter = [0, 0, 0, 0, 0, 0, 0, 1];
                }
                if (secure && command.P1 == 0x41 && command.P2 == 0xa4)
                    _signing = BerTlv.ParseMany(command.Data).Single(x => x.Tag == 0x80).Value[0] == 2;
                break;
            case 0x84: data = _challenge; break;
            case 0x82:
                var proof = CardCrypto.ModPow(command.Data.AsSpan(8), [1, 0, 1], IasConstants.TerminalModulus);
                var hash = SHA256.HashData([..proof[1..^33], .._terminalDh, ..command.Data[..8], .._challenge, .._cardDh, .._g, .._p, .._q]);
                Assert.That(proof[^33..^1], Is.EqualTo(hash), "Terminal authentication proof");
                ExternalProofsVerified++;
                break;
            case 0x88:
                if (_signing) data = _rsa.SignHash(command.Data[^32..], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                else
                {
                    byte[] serial = new byte[8], random = RandomNumberGenerator.GetBytes(222);
                    var hash2 = SHA256.HashData([..random, .._cardDh, ..serial, ..command.Data, .._terminalDh, .._g, .._p, .._q]);
                    if (CorruptInternalProof) hash2[0] ^= 1;
                    var key = _rsa.ExportParameters(true);
                    data = [..serial, ..CardCrypto.ModPow([0x6a, ..random, ..hash2, 0xbc], key.D!, key.Modulus!)];
                    _nextCounter = [.._challenge[4..], ..command.Data[4..]];
                }
                break;
            case 0x20:
                PinVerifications++;
                if (!command.Data.AsSpan().SequenceEqual("12345678"u8)) return new([], 0x63c2);
                break;
            case 0x2a: Assert.That(command.Data.Length, Is.GreaterThan(231), "Terminal certificate is chained"); break;
            default: throw new InvalidOperationException($"Unexpected INS {command.Ins:X2}");
        }
        return new(data, 0x9000);
    }

    private ApduCommand Unprotect(ApduCommand command)
    {
        CardCrypto.Increment(_counter);
        var objects = BerTlv.ParseMany(command.Data);
        byte[] covered = objects.Take(objects.Count - 1).SelectMany(o => o.Encoded).ToArray();
        var expected = CardCrypto.Mac(_mac, CardCrypto.Pad([..CardCrypto.Pad([.._counter, command.Cla, command.Ins, command.P1, command.P2]), ..covered]));
        Assert.That(objects[^1].Value, Is.EqualTo(expected), "Command MAC");
        var encrypted = objects.SingleOrDefault(o => o.Tag is 0x87 or 0x85);
        byte[] data = encrypted is null ? [] : CardCrypto.Unpad(CardCrypto.Des(_enc, encrypted.Tag == 0x87 ? encrypted.Value[1..] : encrypted.Value, false));
        var leObject = objects.SingleOrDefault(o => o.Tag == 0x97);
        int? le = leObject is null ? null : leObject.Value[0] == 0 ? 256 : leObject.Value[0];
        return command with { Data = data, Le = le, Cla = (byte)(command.Cla & ~12) };
    }

    private byte[] Protect(ApduResponse response)
    {
        CardCrypto.Increment(_counter);
        byte[] encrypted = response.Data.Length == 0 ? [] : BerTlv.Encode(0x87, [1, ..CardCrypto.Des(_enc, CardCrypto.Pad(response.Data), true)]);
        byte[] status = BerTlv.Encode(0x99, [(byte)(response.Status >> 8), (byte)response.Status]);
        var mac = CardCrypto.Mac(_mac, CardCrypto.Pad([.._counter, ..encrypted, ..status]));
        if (CorruptMac) mac[0] ^= 1;
        return [..encrypted, ..status, ..BerTlv.Encode(0x8e, mac), 0x90, 0];
    }
    public ValueTask DisposeAsync() { Disposed = true; _rsa.Dispose(); return ValueTask.CompletedTask; }
}

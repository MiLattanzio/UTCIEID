using NUnit.Framework;
using UTCie.Sdk.Card;
using UTCie.Sdk.Crypto;

namespace UTCie.Tests;

public class ProtocolTests
{
    [TestCase(0x6282)]
    [TestCase(0x6b00)]
    public void EndOfFileEnvelopeIsAcceptedOnlyWithAuthenticatedMatchingStatus(int status)
    {
        byte[] enc = Convert.FromHexString("979EC13B1CBFE9DCD01AB0FED307EAE5");
        byte[] mac = Convert.FromHexString("F1CB1F1FB5ADF208806B89DC579DC1F8");
        byte[] do99 = [0x99, 2, (byte)(status >> 8), (byte)status];
        byte[] signature = CardCrypto.Mac(mac, CardCrypto.Pad([0, 0, 0, 0, 0, 0, 0, 2, ..do99]));
        byte[] data = [..do99, 0x8e, 8, ..signature];
        using var valid = new SecureMessaging(enc, mac);
        Assert.That(valid.Unprotect(new(data, (ushort)status)).Status, Is.EqualTo(status));
        using var mismatch = new SecureMessaging(enc, mac);
        Assert.Throws<CardProtocolException>(() => mismatch.Unprotect(new(data, status == 0x6282 ? (ushort)0x6b00 : (ushort)0x6282)));
        data[^1] ^= 1;
        using var forged = new SecureMessaging(enc, mac);
        Assert.Throws<CardProtocolException>(() => forged.Unprotect(new(data, (ushort)status)));
        using var missing = new SecureMessaging(enc, mac);
        Assert.Throws<CardProtocolException>(() => missing.Unprotect(new([], (ushort)status)));
    }

    [TestCase("12345678", true)]
    [TestCase("00000000", true)]
    [TestCase("1234", false)]
    [TestCase("123456789", false)]
    [TestCase("١٢٣٤٥٦٧٨", false)]
    [TestCase("1234567 ", false)]
    public void PinRequiresEightAsciiDigits(string pin, bool expected) => Assert.That(CiePin.IsValid(pin), Is.EqualTo(expected));

    [TestCase("00A40400")]
    [TestCase("00B0000000")]
    [TestCase("00A40204021001")]
    [TestCase("00A4020402100100")]
    public void ApduRoundTrip(string hex)
    {
        var data = Convert.FromHexString(hex);
        Assert.That(ApduCommand.Parse(data).Encode(), Is.EqualTo(data));
    }
    [TestCase("00")]
    [TestCase("00A402040210")]
    [TestCase("00A402040000010001")]
    [TestCase("00A402040110010203")]
    public void MalformedApduRejected(string hex) => Assert.Throws<CardProtocolException>(() => ApduCommand.Parse(Convert.FromHexString(hex)));

    [TestCase(0, 65536)]
    [TestCase(264, 256)]
    [TestCase(264, 0)]
    [TestCase(3, 65536)]
    public void ExtendedApduPreservesLongPacePayloadAndExpectedLength(int length, int le)
    {
        byte[] data = Enumerable.Range(0, length).Select(i => (byte)i).ToArray();
        var original = new ApduCommand(0x10, 0x86, 0, 0, data, le == 0 ? null : le);
        var parsed = ApduCommand.Parse(original.Encode());
        Assert.That(parsed.Data, Is.EqualTo(data));
        Assert.That(parsed.Le, Is.EqualTo(original.Le));
    }

    [TestCase("3080")]
    [TestCase("308201")]
    [TestCase("3082010000")]
    [TestCase("9F8181818100")]
    [TestCase("300102")]
    public void MalformedTlvRejected(string hex)
    {
        Assert.Throws<CardProtocolException>(() => { var tlv = BerTlv.Parse(Convert.FromHexString(hex)); _ = tlv.Children; });
    }
    [TestCase(0)] [TestCase(127)] [TestCase(128)] [TestCase(255)] [TestCase(256)] [TestCase(4096)]
    public void TlvLengths(int length)
    {
        byte[] data = Enumerable.Range(0, length).Select(i => (byte)i).ToArray();
        var tlv = BerTlv.Parse(BerTlv.Encode(0x7f21, data));
        Assert.That(tlv.Tag, Is.EqualTo(0x7f21)); Assert.That(tlv.Value, Is.EqualTo(data));
    }
    [TestCase(0)] [TestCase(1)] [TestCase(7)] [TestCase(8)] [TestCase(16)]
    public void IsoPaddingAlwaysAddsTerminator(int size)
    {
        byte[] data = new byte[size];
        var padded = CardCrypto.Pad(data);
        Assert.That(padded.Length % 8, Is.Zero); Assert.That(padded.Length, Is.GreaterThan(size));
        Assert.That(CardCrypto.Unpad(padded), Is.EqualTo(data));
    }
    [Test] public void MissingPaddingRejected() => Assert.Throws<CardProtocolException>(() => CardCrypto.Unpad(new byte[8]));

    [Test] public void DesKnownAnswer()
    {
        var cipher = CardCrypto.Des(Convert.FromHexString("133457799BBCDFF1"), Convert.FromHexString("0123456789ABCDEF"), true);
        Assert.That(Convert.ToHexString(cipher), Is.EqualTo("85E813540F0AB405"));
    }
    [Test] public void UnsignedModularExponentKeepsLeadingZeroes()
    {
        Assert.That(CardCrypto.ModPow([2], [3], [0x01, 0x01]), Is.EqualTo(new byte[] { 0, 8 }));
        Assert.Throws<CardProtocolException>(() => CardCrypto.ModPow([0xff], [3], [0xfe]));
    }
    [TestCase(0x63c2, 2)] [TestCase(0x63c1, 1)] [TestCase(0x63c0, 0)] [TestCase(0x6983, 0)]
    public void PinStatusUsesUnsignedStatusWords(int status, int attempts) =>
        Assert.That(Assert.Throws<PinException>(() => CieCard.CheckPinStatus((ushort)status))!.RemainingAttempts, Is.EqualTo(attempts));
    [Test] public void TransportFailureIsNotPinBlocked() => Assert.Throws<CardStatusException>(() => CieCard.CheckPinStatus(0x6f00));

    [Test] public async Task GetResponseUsesLatestStatusAndAccumulatesBytes()
    {
        var transcript = new TranscriptTransport(
            ("00A4040C0DA0000000308000000009816001", "9000"),
            ("00A4040406A00000000039", "9000"),
            ("00A40204021001", "9000"),
            ("00B000000C", "010203046104"),
            ("00C0000004", "050607086104"),
            ("00C0000004", "090A0B0C9000"));
        await using var card = new CieCard(transcript);
        Assert.That(await card.ReadServiceIdAsync(), Is.EqualTo("0102030405060708090A0B0C"));
        Assert.That(transcript.Remaining, Is.Zero);
    }
    [Test] public async Task InvalidPinNeverTouchesCard()
    {
        var transport = new TranscriptTransport();
        await using var card = new CieCard(transport);
        Assert.ThrowsAsync<ArgumentException>(async () => await card.OpenSecureChannelAsync("1234".AsMemory()));
    }
    [Test] public async Task WrongApplicationStopsImmediately()
    {
        var transport = new TranscriptTransport(("00A4040C0DA0000000308000000009816001", "9000"), ("00A4040406A00000000039", "6A82"));
        await using var card = new CieCard(transport);
        Assert.ThrowsAsync<NotCieException>(async () => await card.ReadServiceIdAsync());
        Assert.That(transport.Remaining, Is.Zero);
    }
    [Test] public async Task MissingPreliminaryIasAidStillChecksCieApplication()
    {
        var transport = new TranscriptTransport(
            ("00A4040C0DA0000000308000000009816001", "6A82"),
            ("00A4040406A00000000039", "9000"),
            ("00A40204021001", "9000"),
            ("00B000000C", "0102030405060708090A0B0C9000"));
        await using var card = new CieCard(transport);
        Assert.That(await card.ReadServiceIdAsync(), Has.Length.EqualTo(24));
    }
    [Test] public void SequenceCounterIsPerSessionAndInvalidResponseKillsSession()
    {
        var enc = Convert.FromHexString("AB94FDECF2674FDFB9B391F85D7F76F2");
        var mac = Convert.FromHexString("7962D9ECE03D1ACD4C76089DCE131543");
        using var first = new SecureMessaging(enc, mac);
        using var second = new SecureMessaging(enc, mac);
        var command = new ApduCommand(0, 0xa4, 2, 0x0c, [1, 0x1e], null);
        var firstMessage = first.Protect(command);
        Assert.That(second.Protect(command), Is.EqualTo(firstMessage));
        Assert.Throws<CardProtocolException>(() => first.Unprotect(new([0x99, 2, 0x90, 0], 0x9000)));
        Assert.Throws<ObjectDisposedException>(() => first.Protect(command));
        Assert.DoesNotThrow(() => second.Protect(command));
    }
    [Test] public void SecureMessagingIcaoKnownAnswer()
    {
        using var sm = new SecureMessaging(Convert.FromHexString("979EC13B1CBFE9DCD01AB0FED307EAE5"), Convert.FromHexString("F1CB1F1FB5ADF208806B89DC579DC1F8"));
        sm.SetCounter(Convert.FromHexString("887022120C06C226"));
        var command = new ApduCommand(0, 0xa4, 2, 0x0c, [1, 0x1e], null);
        Assert.That(Convert.ToHexString(sm.Protect(command)), Is.EqualTo("0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800"));
        var result = sm.Unprotect(ApduResponse.Parse(Convert.FromHexString("990290008E08FA855A5D4C50A8ED9000")));
        Assert.That(result.Status, Is.EqualTo(0x9000));
    }
}

internal sealed class TranscriptTransport(params (string Command, string Response)[] steps) : ICardTransport
{
    private readonly Queue<(string Command, string Response)> _steps = new(steps);
    public int Remaining => _steps.Count;
    public ValueTask<byte[]> TransceiveAsync(ReadOnlyMemory<byte> command, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Assert.That(_steps.Count, Is.GreaterThan(0), "Unexpected card command");
        var next = _steps.Dequeue();
        Assert.That(Convert.ToHexString(command.Span), Is.EqualTo(next.Command));
        return ValueTask.FromResult(Convert.FromHexString(next.Response));
    }
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

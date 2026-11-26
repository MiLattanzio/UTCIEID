// C# port of IPZS cieid-android-sdk Ias.kt (BSD-3-Clause).
using System.Numerics;
using System.Security.Cryptography;
using UTCie.Sdk.Crypto;

namespace UTCie.Sdk.Card;

/// <summary>IAS/CIE 3.0 protocol session. One operation at a time, one physical card per instance.</summary>
public sealed class CieCard(ICardTransport transport) : IAsyncDisposable
{
    private SecureMessaging? _sm;
    private byte[] _g = [], _p = [], _q = [], _terminalDh = [], _cardDh = [];
    private byte[] _cardModulus = [], _cardExponent = [], _caModulus = [], _caCar = [], _caAid = [];
    private bool _pinVerified, _disposed;
    private int _busy;

    public Task<string> ReadServiceIdAsync(CancellationToken token = default) => RunAsync(async () =>
    {
        ResetChannel();
        // Match getIdServizi in the Android SDK: CIE SELECT requests FCI (P2=04).
        await SelectApplicationsAsync(token, requestFci: true);
        (await SendAsync(0xa4, 0x02, 0x04, [0x10, 0x01], null, false, token)).RequireSuccess();
        var id = (await SendAsync(0xb0, 0, 0, [], 12, false, token)).RequireSuccess();
        if (id.Length != 12) throw new CardProtocolException("Il file servizi della CIE ha una lunghezza inattesa.");
        return Convert.ToHexString(id);
    });

    public Task OpenSecureChannelAsync(ReadOnlyMemory<char> pin, CancellationToken token = default) => RunAsync(async () =>
    {
        if (!CiePin.IsValid(pin.Span)) throw new ArgumentException("Il PIN CIE deve contenere esattamente 8 cifre.", nameof(pin));
        ResetChannel();
        await PrepareChannelAsync(token);
        var pinBytes = new byte[8];
        try
        {
            for (int i = 0; i < 8; i++) pinBytes[i] = (byte)pin.Span[i];
            var response = await SendAsync(0x20, 0, 0x81, pinBytes, null, true, token);
            CheckPinStatus(response.Status);
            _pinVerified = true;
        }
        finally { CryptographicOperations.ZeroMemory(pinBytes); }
        return true;
    });

    /// <summary>Diagnostic preparation of DH/DAPP only. Never sends VERIFY PIN or reads personal certificates.</summary>
    public Task ProbeSecureChannelAsync(CancellationToken token = default) => RunAsync(async () =>
    {
        ResetChannel();
        await PrepareChannelAsync(token);
        return true;
    });

    private async Task PrepareChannelAsync(CancellationToken token)
    {
        await SelectApplicationsAsync(token);
        _g = await ReadDhParameterAsync(0x97, token);
        _p = await ReadDhParameterAsync(0x98, token);
        _q = await ReadDhParameterAsync(0x99, token);
        ValidateDhParameters();
        var key = BerTlv.Parse(await ReadFileAsync(0x1004, false, token));
        // An RSA SEQUENCE contains two INTEGERs. Select by position, validate both tags.
        var integers = key.Children;
        if (integers.Count != 2 || integers.Any(x => x.Tag != 2)) throw new CardProtocolException("Chiave DAPP non valida.");
        _cardModulus = TrimInteger(integers[0].Value);
        _cardExponent = TrimInteger(integers[1].Value);
        if (_cardModulus.Length is < 128 or > 512) throw new CardProtocolException("Modulo DAPP non valido.");

        var ca = BerTlv.Parse((await SendAsync(0xcb, 0x3f, 0xff, Convert.FromHexString("4D097007BFA004037F4980"), null, false, token)).RequireSuccess())
            .Children[0].Children[0];
        _caModulus = ca.Child(0x81).Value;
        var chr = ca.Child(0x5f20).Value;
        var cha = ca.Child(0x5f4c).Value;
        if (_caModulus.Length != 256 || chr.Length < 5 || cha.Length < 6) throw new CardProtocolException("Parametri terminale non validi.");
        _caCar = chr[4..]; _caAid = cha[..6];
        await ExchangeKeysAsync(token);
        await AuthenticateDeviceAsync(token);
    }

    public Task<byte[]> ReadCertificateAsync(CancellationToken token = default) => RunAsync(async () =>
    {
        RequirePin();
        return await ReadFileAsync(0x1003, true, token);
    });

    /// <summary>Signs a SHA-256 digest with the CIE authentication key; never exports the private key.</summary>
    public Task<byte[]> SignSha256Async(ReadOnlyMemory<byte> digest, CancellationToken token = default) => RunAsync(async () =>
    {
        RequirePin();
        if (digest.Length != 32) throw new ArgumentException("Il digest SHA-256 deve avere 32 byte.", nameof(digest));
        (await SendAsync(0x22, 0x41, 0xa4, Convert.FromHexString("800102840181"), null, true, token)).RequireSuccess();
        byte[] digestInfo = [..Convert.FromHexString("3031300D060960864801650304020105000420"), ..digest.Span];
        return (await SendAsync(0x88, 0, 0, digestInfo, null, true, token)).RequireSuccess();
    });

    internal static void CheckPinStatus(ushort status)
    {
        if (status == 0x9000) return;
        if ((status & 0xfff0) == 0x63c0) throw new PinException(status & 15);
        if (status == 0x6983) throw new PinException(0);
        throw new CardStatusException(status);
    }

    private async Task SelectApplicationsAsync(CancellationToken token, bool requestFci = false)
    {
        var ias = await SendAsync(0xa4, 0x04, 0x0c, Convert.FromHexString("A0000000308000000009816001"), null, false, token);
        // The Android SDK continues to CIE SELECT even if the preliminary IAS application is absent.
        if (ias.Status != 0x6a82) ias.RequireSuccess();
        var cie = await SendAsync(0xa4, 0x04, requestFci ? (byte)0x04 : (byte)0x0c, Convert.FromHexString("A00000000039"), null, false, token);
        if (cie.Status == 0x6a82) throw new NotCieException();
        cie.RequireSuccess();
    }

    private async Task<byte[]> ReadDhParameterAsync(byte id, CancellationToken token)
    {
        byte[] request = [0x4d, 0x0a, 0x70, 0x08, 0xbf, 0xa1, 0x01, 0x04, 0xa3, 0x02, id, 0];
        var root = BerTlv.Parse((await SendAsync(0xcb, 0x3f, 0xff, request, null, false, token)).RequireSuccess());
        var parameter = root.Children[0].Children[0].Children[0];
        if (parameter.Tag != id || parameter.Value.Length == 0) throw new CardProtocolException("Parametro DH inatteso.");
        return parameter.Value;
    }

    private void ValidateDhParameters()
    {
        var p = new BigInteger(_p, true, true);
        var q = new BigInteger(_q, true, true);
        var g = new BigInteger(_g, true, true);
        if (_p.Length is < 128 or > 512 || _q.Length is < 16 or > 512 || _q[0] == 0 || q >= p || g <= 1 || g >= p - 1 ||
            (p - 1) % q != 0 || BigInteger.ModPow(g, q, p) != 1)
            throw new CardProtocolException("Gruppo Diffie-Hellman non valido.");
    }

    private async Task ExchangeKeysAsync(CancellationToken token)
    {
        var secretExponent = CardCrypto.RandomExponent(_q);
        byte[] secret = [];
        try
        {
            _terminalDh = CardCrypto.ModPow(_g, secretExponent, _p);
            byte[] data = [..BerTlv.Encode(0x80, [0x9b]), ..BerTlv.Encode(0x83, [0x81]), ..BerTlv.Encode(0x91, _terminalDh)];
            (await SendAsync(0x22, 0x41, 0xa6, data, null, false, token)).RequireSuccess();
            var root = BerTlv.Parse((await SendAsync(0xcb, 0x3f, 0xff, Convert.FromHexString("4D04A6029100"), null, false, token)).RequireSuccess());
            _cardDh = root.Child(0x91).Value;
            var y = new BigInteger(_cardDh, true, true);
            var p = new BigInteger(_p, true, true);
            if (_cardDh.Length != _p.Length || y <= 1 || y >= p - 1 || BigInteger.ModPow(y, new BigInteger(_q, true, true), p) != 1)
                throw new CardProtocolException("Chiave DH della carta non valida.");
            secret = CardCrypto.ModPow(_cardDh, secretExponent, _p);
            byte[] encInput = [..secret, 0, 0, 0, 1], macInput = [..secret, 0, 0, 0, 2];
            byte[] enc = SHA256.HashData(encInput), mac = SHA256.HashData(macInput);
            try { _sm = new SecureMessaging(enc[..16], mac[..16]); }
            finally
            {
                CryptographicOperations.ZeroMemory(encInput); CryptographicOperations.ZeroMemory(macInput);
                CryptographicOperations.ZeroMemory(enc); CryptographicOperations.ZeroMemory(mac);
            }
        }
        finally { CryptographicOperations.ZeroMemory(secretExponent); CryptographicOperations.ZeroMemory(secret); }
    }

    private async Task AuthenticateDeviceAsync(CancellationToken token)
    {
        byte[] serial = [0x20, 0, 0, 0, 0, 0, 0, 1];
        byte[] chr = [0, 0, 0, 0, ..serial];
        byte[] body = [0x8a, .._caCar, ..chr, .._caAid, 1, ..Convert.FromHexString("2A8122F42A02040104"),
            ..IasConstants.TerminalModulus, 0, 1, 0, 1];
        int recoveredLength = _caModulus.Length - 34;
        byte[] signature = CardCrypto.ModPow([0x6a, ..body[..recoveredLength], ..SHA256.HashData(body), 0xbc], IasConstants.AuthorityExponent, _caModulus);
        byte[] certificate = BerTlv.Encode(0x7f21, [..BerTlv.Encode(0x5f37, signature),
            ..BerTlv.Encode(0x5f38, body[recoveredLength..]), ..BerTlv.Encode(0x42, _caCar)]);
        (await SendAsync(0x22, 0x81, 0xb6, Convert.FromHexString("800141830184"), null, true, token)).RequireSuccess();
        (await SendAsync(0x2a, 0, 0xae, certificate, null, true, token)).RequireSuccess();
        (await SendAsync(0x22, 0x81, 0xa4, BerTlv.Encode(0x83, chr), null, true, token)).RequireSuccess();
        var challenge = (await SendAsync(0x84, 0, 0, [], 8, true, token)).RequireSuccess();
        if (challenge.Length != 8) throw new CardProtocolException("Challenge carta non valida.");
        byte[] random = RandomNumberGenerator.GetBytes(IasConstants.TerminalModulus.Length - 34);
        byte[] hash = SHA256.HashData([..random, .._terminalDh, ..serial, ..challenge, .._cardDh, .._g, .._p, .._q]);
        var proof = CardCrypto.ModPow([0x6a, ..random, ..hash, 0xbc], IasConstants.TerminalExponent, IasConstants.TerminalModulus);
        (await SendAsync(0x82, 0, 0, [..serial, ..proof], null, true, token)).RequireSuccess();
        (await SendAsync(0x22, 0x41, 0xa4, Convert.FromHexString("84018280019B"), null, true, token)).RequireSuccess();
        var nonce = RandomNumberGenerator.GetBytes(8);
        var response = (await SendAsync(0x88, 0, 0, nonce, null, true, token)).RequireSuccess();
        if (response.Length != 8 + _cardModulus.Length) throw new CardProtocolException("Prova DAPP non valida.");
        var recovered = CardCrypto.ModPow(response.AsSpan(8), _cardExponent, _cardModulus);
        if (recovered[0] != 0x6a || recovered[^1] != 0xbc) throw new CardProtocolException("Autenticazione del chip fallita.");
        byte[] expected = SHA256.HashData([..recovered[1..^33], .._cardDh, ..response[..8], ..nonce, .._terminalDh, .._g, .._p, .._q]);
        if (!CryptographicOperations.FixedTimeEquals(expected, recovered.AsSpan(recovered.Length - 33, 32)))
            throw new CardProtocolException("Autenticazione del chip fallita.");
        _sm!.SetCounter([..challenge[4..], ..nonce[4..]]);
    }

    private async Task<byte[]> ReadFileAsync(ushort id, bool secure, CancellationToken token)
    {
        (await SendAsync(0xa4, 2, 4, [(byte)(id >> 8), (byte)id], null, secure, token)).RequireSuccess();
        using var content = new MemoryStream();
        while (content.Length < 32768)
        {
            int offset = (int)content.Length;
            var response = await SendAsync(0xb0, (byte)(offset >> 8), (byte)offset, [], 256, secure, token);
            if ((response.Status & 0xff00) == 0x6c00)
                response = await SendAsync(0xb0, (byte)(offset >> 8), (byte)offset, [], (response.Status & 255) == 0 ? 256 : response.Status & 255, secure, token);
            if (response.Status == 0x6b00 && content.Length != 0) return content.ToArray();
            if (response.Status is not (0x9000 or 0x6282)) throw new CardStatusException(response.Status);
            if (response.Data.Length > 256) throw new CardProtocolException("Blocco file troppo grande.");
            content.Write(response.Data);
            if (response.Status == 0x6282) return content.ToArray();
            if (response.Data.Length == 0) throw new CardProtocolException("Lettura carta senza avanzamento.");
        }
        throw new CardProtocolException("File carta oltre il limite supportato.");
    }

    private async Task<ApduResponse> SendAsync(byte ins, byte p1, byte p2, byte[] data, int? le, bool secure, CancellationToken token)
    {
        int limit = secure ? 231 : 255, offset = 0;
        ApduResponse result;
        do
        {
            int count = Math.Min(data.Length - offset, limit);
            bool last = offset + count == data.Length;
            var command = new ApduCommand(last ? (byte)0 : (byte)0x10, ins, p1, p2, data.AsSpan(offset, count).ToArray(), last ? le : null);
            byte[] encoded;
            try { encoded = secure ? _sm!.Protect(command) : command.Encode(); }
            finally { CryptographicOperations.ZeroMemory(command.Data); }
            result = await ExchangeAsync(encoded, token);
            if (secure) result = _sm!.Unprotect(result);
            offset += count;
            if (last) return result;
            result.RequireSuccess();
        } while (true);
    }

    private async Task<ApduResponse> ExchangeAsync(byte[] encoded, CancellationToken token)
    {
        var response = ApduResponse.Parse(await transport.TransceiveAsync(encoded, token));
        using var all = new MemoryStream();
        all.Write(response.Data);
        int count = 0;
        while ((response.Status & 0xff00) == 0x6100)
        {
            if (++count > 256 || all.Length > 65536) throw new CardProtocolException("Catena GET RESPONSE troppo lunga.");
            response = ApduResponse.Parse(await transport.TransceiveAsync(new byte[] { 0, 0xc0, 0, 0, (byte)response.Status }, token));
            all.Write(response.Data);
        }
        if (all.Length > 65536) throw new CardProtocolException("Risposta carta troppo grande.");
        return new(all.ToArray(), response.Status);
    }

    private static byte[] TrimInteger(byte[] value)
    {
        int i = 0;
        while (i < value.Length - 1 && value[i] == 0) i++;
        if (value.Length == 0) throw new CardProtocolException("Intero vuoto.");
        return value[i..];
    }
    private void RequirePin() { if (!_pinVerified) throw new InvalidOperationException("Aprire prima il canale sicuro con il PIN."); }
    private void ResetChannel() { _pinVerified = false; _sm?.Dispose(); _sm = null; }
    private async Task<T> RunAsync<T>(Func<Task<T>> action)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (Interlocked.CompareExchange(ref _busy, 1, 0) != 0) throw new InvalidOperationException("Operazione carta già in corso.");
        try { return await action().ConfigureAwait(false); }
        catch { ResetChannel(); throw; }
        finally { Volatile.Write(ref _busy, 0); }
    }
    public async ValueTask DisposeAsync()
    {
        _disposed = true;
        ResetChannel();
        await transport.DisposeAsync().ConfigureAwait(false);
    }
}

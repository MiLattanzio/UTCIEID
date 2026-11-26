// Port of IPZS cieid-android-sdk Ias.sm/respSM, with strict response authentication.
using System.Buffers.Binary;
using System.Security.Cryptography;
using UTCie.Sdk.Card;

namespace UTCie.Sdk.Crypto;

internal sealed class SecureMessaging(byte[] encryptionKey, byte[] macKey) : IDisposable
{
    private readonly byte[] _enc = encryptionKey.ToArray();
    private readonly byte[] _mac = macKey.ToArray();
    private readonly byte[] _counter = [0, 0, 0, 0, 0, 0, 0, 1];
    private bool _disposed;

    public void SetCounter(ReadOnlySpan<byte> counter)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (counter.Length != 8) throw new ArgumentException("SSC deve avere 8 byte.");
        counter.CopyTo(_counter);
    }

    public byte[] Protect(ApduCommand command)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        CardCrypto.Increment(_counter);
        byte[] header = [(byte)(command.Cla | 0x0c), command.Ins, command.P1, command.P2];
        byte[] data = [];
        if (command.Data.Length != 0)
        {
            var padded = CardCrypto.Pad(command.Data);
            byte[] encrypted;
            try { encrypted = CardCrypto.Des(_enc, padded, true); }
            finally { CryptographicOperations.ZeroMemory(padded); }
            data = (command.Ins & 1) == 0 ? BerTlv.Encode(0x87, [1, ..encrypted]) : BerTlv.Encode(0x85, encrypted);
        }
        if (command.Le.HasValue) data = [..data, ..BerTlv.Encode(0x97, [(byte)(command.Le.Value & 255)])];
        var signature = CardCrypto.Mac(_mac, CardCrypto.Pad([..CardCrypto.Pad([.._counter, ..header]), ..data]));
        return new ApduCommand(header[0], header[1], header[2], header[3], [..data, ..BerTlv.Encode(0x8e, signature)], 256).Encode();
    }

    public ApduResponse Unprotect(ApduResponse response)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        try
        {
            // IAS may repeat a READ BINARY end-of-file status in the outer envelope.
            // As in Android getRespSM, parse it, but always authenticate DO99 before trusting it.
            if (response.Status is not (0x9000 or 0x6282 or 0x6b00)) throw new CardStatusException(response.Status);
            CardCrypto.Increment(_counter);
            var objects = BerTlv.ParseMany(response.Data);
            if (objects.Count is < 2 or > 3) throw Invalid();
            var status = objects[^2];
            var signature = objects[^1];
            if (status.Tag != 0x99 || status.Value.Length != 2 || signature.Tag != 0x8e || signature.Value.Length != 8)
                throw Invalid();
            byte[] encrypted = objects.Count == 3 ? objects[0].Encoded : [];
            var expected = CardCrypto.Mac(_mac, CardCrypto.Pad([.._counter, ..encrypted, ..status.Encoded]));
            if (!CryptographicOperations.FixedTimeEquals(expected, signature.Value)) throw Invalid();
            ushort authenticatedStatus = BinaryPrimitives.ReadUInt16BigEndian(status.Value);
            if (response.Status != 0x9000 && response.Status != authenticatedStatus) throw Invalid();
            byte[] clear = [];
            if (objects.Count == 3)
            {
                var obj = objects[0];
                var bytes = obj.Value.AsSpan();
                if (obj.Tag == 0x87 && bytes.Length > 0 && bytes[0] == 1) bytes = bytes[1..];
                else if (obj.Tag != 0x85) throw Invalid();
                if (bytes.Length == 0 || bytes.Length % 8 != 0) throw Invalid();
                var padded = CardCrypto.Des(_enc, bytes, false);
                try { clear = CardCrypto.Unpad(padded); }
                finally { CryptographicOperations.ZeroMemory(padded); }
            }
            return new(clear, authenticatedStatus);
        }
        catch { Dispose(); throw; }
    }

    private static CardProtocolException Invalid() => new("Risposta del canale sicuro non autentica o non valida.");
    public void Dispose()
    {
        _disposed = true;
        CryptographicOperations.ZeroMemory(_enc);
        CryptographicOperations.ZeroMemory(_mac);
        CryptographicOperations.ZeroMemory(_counter);
    }
}

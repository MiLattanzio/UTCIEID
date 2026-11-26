// Adapted from emrtd-dotnet, Copyright (c) 2026 Chamnan Nop, MIT. See licenses/emrtd-dotnet.txt.
using System.Security.Cryptography;

namespace UTCie.Sdk.Icao;

internal sealed class SecureMessaging : IDisposable
{
    private readonly byte[] _enc, _mac, _ssc;
    private bool _disposed;
    public SmCipher Cipher { get; }
    internal byte[] Ssc => _ssc.ToArray();
    private int BlockSize => Crypto.BlockSize(Cipher);
    public SecureMessaging(SmCipher cipher, byte[] enc, byte[] mac, byte[] ssc)
    {
        Cipher = cipher; _enc = enc.ToArray(); _mac = mac.ToArray(); _ssc = ssc.ToArray();
        if (ssc.Length != BlockSize) throw new ArgumentException("SSC non valido.");
    }

    public byte[] Wrap(CommandApdu command)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        Increment();
        byte cla = (byte)(command.Cla | 0x0c);
        byte[] header = Crypto.Pad([cla, command.Ins, command.P1, command.P2], BlockSize);
        byte[] objects = [];
        if (command.Data is { Length: > 0 } data)
        {
            byte[] padded = Crypto.Pad(data, BlockSize);
            byte[] encrypted;
            try { encrypted = Crypto.Encrypt(Cipher, _enc, padded, Iv()); }
            finally { CryptographicOperations.ZeroMemory(padded); }
            objects = (command.Ins & 1) == 0 ? Tlv.Encode(0x87, [1, ..encrypted]) : Tlv.Encode(0x85, encrypted);
        }
        if (command.Ne is int ne) objects = [..objects, ..Tlv.Encode(0x97, [(byte)ne])];
        byte[] mac = Crypto.Mac(Cipher, _mac, Crypto.Pad([.._ssc, ..header, ..objects], BlockSize));
        return new CommandApdu(cla, command.Ins, command.P1, command.P2, [..objects, ..Tlv.Encode(0x8e, mac)], 256).Encode();
    }

    public ResponseApdu Unwrap(byte[] raw)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        try
        {
            Increment();
            var response = ResponseApdu.Parse(raw);
            if (response.SW is not (0x9000 or 0x6282)) throw new CardException(response.SW, "Canale ICAO interrotto");
            var objects = Tlv.ParseAll(response.Data);
            if (objects.Count is < 2 or > 3 || objects[^2].Tag != 0x99 || objects[^2].Value.Length != 2 || objects[^1].Tag != 0x8e || objects[^1].Value.Length != 8)
                throw Invalid();
            var status = objects[^2];
            byte[] encoded = objects.Count == 3 ? objects[0].Encode() : [];
            var expected = Crypto.Mac(Cipher, _mac, Crypto.Pad([.._ssc, ..encoded, ..status.Encode()], BlockSize));
            if (!CryptographicOperations.FixedTimeEquals(expected, objects[^1].Value)) throw Invalid();
            ushort sw = (ushort)(status.Value[0] << 8 | status.Value[1]);
            if (response.SW != 0x9000 && response.SW != sw) throw Invalid();
            byte[] clear = [];
            if (objects.Count == 3)
            {
                var obj = objects[0];
                ReadOnlySpan<byte> bytes = obj.Value;
                if (obj.Tag == 0x87 && bytes.Length > 0 && bytes[0] == 1) bytes = bytes[1..];
                else if (obj.Tag != 0x85) throw Invalid();
                if (bytes.Length == 0 || bytes.Length % BlockSize != 0) throw Invalid();
                byte[] padded = Crypto.Decrypt(Cipher, _enc, bytes, Iv());
                try { clear = Crypto.Unpad(padded); }
                finally { CryptographicOperations.ZeroMemory(padded); }
            }
            return new(clear, sw);
        }
        catch { Dispose(); throw; }
    }

    private byte[] Iv() => Cipher == SmCipher.TripleDes ? new byte[8] : Crypto.AesEcb(_enc, _ssc);
    private void Increment() { for (int i = _ssc.Length - 1; i >= 0; i--) if (++_ssc[i] != 0) return; throw Invalid(); }
    private static CryptographicException Invalid() => new("Risposta ICAO non autentica o non valida.");
    public void Dispose() { _disposed = true; CryptographicOperations.ZeroMemory(_enc); CryptographicOperations.ZeroMemory(_mac); CryptographicOperations.ZeroMemory(_ssc); }
}

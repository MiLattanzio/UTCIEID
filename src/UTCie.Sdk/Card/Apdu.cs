using System.Buffers.Binary;

namespace UTCie.Sdk.Card;

internal readonly record struct ApduResponse(byte[] Data, ushort Status)
{
    public static ApduResponse Parse(ReadOnlySpan<byte> response)
    {
        if (response.Length < 2 || response.Length > 65538)
            throw new CardProtocolException("Risposta APDU non valida.");
        return new(response[..^2].ToArray(), BinaryPrimitives.ReadUInt16BigEndian(response[^2..]));
    }

    public byte[] RequireSuccess()
    {
        if (Status != 0x9000) throw new CardStatusException(Status);
        return Data;
    }
}

/// <summary>ISO 7816 short/extended APDU. Zero Le means 256/65536; null means absent.</summary>
public sealed record ApduCommand(byte Cla, byte Ins, byte P1, byte P2, byte[] Data, int? Le)
{
    public byte[] Encode()
    {
        if (Data.Length > 65535 || Le is < 1 or > 65536) throw new ArgumentOutOfRangeException(nameof(Data));
        if (Data.Length > 255 || Le > 256)
        {
            byte[] extended = new byte[7 + Data.Length + (Data.Length > 0 && Le.HasValue ? 2 : 0)];
            extended[0] = Cla; extended[1] = Ins; extended[2] = P1; extended[3] = P2;
            if (Data.Length > 0)
            {
                BinaryPrimitives.WriteUInt16BigEndian(extended.AsSpan(5), (ushort)Data.Length);
                Data.CopyTo(extended, 7);
            }
            if (Le.HasValue) BinaryPrimitives.WriteUInt16BigEndian(extended.AsSpan(extended.Length - 2), (ushort)(Le.Value & 65535));
            return extended;
        }
        byte[] result = new byte[4 + (Data.Length > 0 ? 1 + Data.Length : 0) + (Le.HasValue ? 1 : 0)];
        result[0] = Cla; result[1] = Ins; result[2] = P1; result[3] = P2;
        if (Data.Length > 0) { result[4] = (byte)Data.Length; Data.CopyTo(result, 5); }
        if (Le.HasValue) result[^1] = (byte)(Le.Value & 255);
        return result;
    }

    public static ApduCommand Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 4) throw new CardProtocolException("APDU troppo corta.");
        byte[] data = [];
        int? le = null;
        if (bytes.Length == 5) le = bytes[4] == 0 ? 256 : bytes[4];
        else if (bytes.Length > 5)
        {
            int lc = bytes[4];
            if (lc == 0)
            {
                if (bytes.Length < 7) throw new CardProtocolException("APDU estesa troncata.");
                int length = BinaryPrimitives.ReadUInt16BigEndian(bytes[5..]);
                if (bytes.Length == 7) le = length == 0 ? 65536 : length;
                else
                {
                    if (length == 0 || (bytes.Length != 7 + length && bytes.Length != 9 + length)) throw new CardProtocolException("Lunghezza APDU estesa non valida.");
                    data = bytes.Slice(7, length).ToArray();
                    if (bytes.Length == 9 + length)
                    {
                        int expected = BinaryPrimitives.ReadUInt16BigEndian(bytes[^2..]);
                        le = expected == 0 ? 65536 : expected;
                    }
                }
            }
            else
            {
                if (bytes.Length != 5 + lc && bytes.Length != 6 + lc) throw new CardProtocolException("Lunghezza APDU non valida.");
                data = bytes.Slice(5, lc).ToArray();
                if (bytes.Length == 6 + lc) le = bytes[^1] == 0 ? 256 : bytes[^1];
            }
        }
        return new(bytes[0], bytes[1], bytes[2], bytes[3], data, le);
    }
}

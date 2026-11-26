using UTCie.Sdk.Card;

namespace UTCie.Sdk.Crypto;

/// <summary>Bounded BER-TLV reader for the definite-length IAS objects.</summary>
internal sealed record BerTlv(int Tag, byte[] Value, byte[] Encoded)
{
    public IReadOnlyList<BerTlv> Children => ParseMany(Value);
    public BerTlv Child(int tag) => Children.SingleOrDefault(t => t.Tag == tag)
        ?? throw new CardProtocolException($"Oggetto carta {tag:X} assente o duplicato.");

    public static BerTlv Parse(ReadOnlySpan<byte> bytes)
    {
        var tags = ParseMany(bytes);
        if (tags.Count != 1) throw new CardProtocolException("Oggetto BER non univoco.");
        return tags[0];
    }

    public static IReadOnlyList<BerTlv> ParseMany(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length > 65536) throw new CardProtocolException("Oggetto BER troppo grande.");
        List<BerTlv> result = [];
        int offset = 0;
        while (offset < bytes.Length)
        {
            int start = offset, tag = bytes[offset++];
            if ((tag & 31) == 31)
            {
                int count = 0;
                byte next;
                do
                {
                    if (offset >= bytes.Length || ++count > 3) throw Invalid();
                    next = bytes[offset++];
                    tag = (tag << 8) | next;
                } while ((next & 128) != 0);
            }
            if (offset >= bytes.Length) throw Invalid();
            int length = bytes[offset++];
            if ((length & 128) != 0)
            {
                int count = length & 127;
                if (count is 0 or > 3 || offset + count > bytes.Length) throw Invalid();
                length = 0;
                for (int i = 0; i < count; i++) length = (length << 8) | bytes[offset++];
            }
            if (length > bytes.Length - offset || result.Count >= 1024) throw Invalid();
            result.Add(new(tag, bytes.Slice(offset, length).ToArray(), bytes.Slice(start, offset - start + length).ToArray()));
            offset += length;
        }
        return result;
    }

    public static byte[] Encode(int tag, ReadOnlySpan<byte> value)
    {
        if (tag <= 0 || value.Length > 65535) throw new ArgumentOutOfRangeException(nameof(tag));
        List<byte> header = [];
        for (int shift = 24; shift >= 0; shift -= 8)
            if (tag >> shift != 0) header.Add((byte)(tag >> shift));
        if (value.Length < 128) header.Add((byte)value.Length);
        else if (value.Length <= 255) header.AddRange([0x81, (byte)value.Length]);
        else header.AddRange([0x82, (byte)(value.Length >> 8), (byte)value.Length]);
        return [..header, ..value];
    }

    private static CardProtocolException Invalid() => new("Codifica BER della carta non valida.");
}

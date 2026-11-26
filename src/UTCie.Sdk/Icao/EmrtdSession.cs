namespace UTCie.Sdk.Icao;

/// <summary>Bounded synchronous protocol driver, run on a worker with a cancellable NFC transport.</summary>
internal sealed class EmrtdSession(Func<byte[], byte[]> transmit) : IDisposable
{
    private SecureMessaging? _sm;
    public void StartSecureMessaging(SecureMessaging sm) { _sm?.Dispose(); _sm = sm; }
    public void Dispose() => _sm?.Dispose();

    public ResponseApdu Send(CommandApdu command)
    {
        byte[] wire = _sm is null ? command.Encode() : _sm.Wrap(command);
        var response = ResponseApdu.Parse(transmit(wire));
        if (_sm is null && (response.SW & 0xff00) == 0x6c00 && command.Ne.HasValue)
            response = ResponseApdu.Parse(transmit((command with { Ne = (response.SW & 255) is 0 ? 256 : response.SW & 255 }).Encode()));
        var data = new List<byte>();
        for (int i = 0; (response.SW & 0xff00) == 0x6100; i++)
        {
            if (i >= 256 || data.Count > 65536) throw new FormatException("Risposta ICAO troppo lunga.");
            data.AddRange(response.Data);
            response = ResponseApdu.Parse(transmit([0, 0xc0, 0, 0, (byte)response.SW]));
        }
        if (data.Count != 0) response = response with { Data = [..data, ..response.Data] };
        return _sm is null ? response : _sm.Unwrap(response.Encode());
    }

    public void SelectMasterFile() => Send(new(0, 0xa4, 0, 0x0c, [0x3f, 0])).EnsureSuccess("Selezione MF");
    public void SelectApplet() => Send(new(0, 0xa4, 4, 0x0c, [0xa0, 0, 0, 2, 0x47, 0x10, 1], 256)).EnsureSuccess("Selezione ICAO");

    public byte[] ReadFile(ushort fileId)
    {
        // Only the public CardAccess, MRZ, portrait and signed security object are read. Never DG3/DG4.
        if (fileId is not (0x011c or 0x0101 or 0x0102 or 0x011d)) throw new ArgumentOutOfRangeException(nameof(fileId));
        byte[] header;
        if (fileId == 0x011c)
        {
            Send(new(0, 0xa4, 2, 0x0c, [1, 0x1c])).EnsureSuccess("Selezione CardAccess");
            header = ReadBinary(0, 8);
        }
        else
        {
            // ICAO short file identifiers select the current EF as they read, as in the CIE MRTD SDK.
            header = Send(new(0, 0xb0, (byte)(0x80 | (fileId & 0x1f)), 0, Ne: 8)).EnsureSuccess($"Lettura file ICAO {fileId:X4}").Data;
        }
        int total = Tlv.TotalLength(header);
        int limit = fileId == 0x0102 ? 1048576 : 65536;
        if (total <= 0 || total > limit) throw new FormatException("Dimensione file ICAO non valida.");
        if (header.Length >= total) return header[..total];
        var result = new byte[total];
        header.CopyTo(result, 0);
        for (int offset = header.Length; offset < total;)
        {
            int count = Math.Min(219, total - offset);
            byte[] chunk = ReadBinary(offset, count);
            if (chunk.Length == 0 || chunk.Length > count) throw new FormatException("Lunghezza risposta ICAO non valida.");
            chunk.CopyTo(result, offset);
            offset += chunk.Length;
        }
        return result;
    }

    private byte[] ReadBinary(int offset, int count)
    {
        if (offset <= 0x7fff)
            return Send(new(0, 0xb0, (byte)(offset >> 8), (byte)offset, Ne: count)).EnsureSuccess("Lettura ICAO").Data;
        byte[] address = offset <= 0xffff ? [(byte)(offset >> 8), (byte)offset] : [(byte)(offset >> 16), (byte)(offset >> 8), (byte)offset];
        var response = Send(new(0, 0xb1, 0, 0, Tlv.Encode(0x54, address), count + (count < 128 ? 2 : 3))).EnsureSuccess("Lettura ICAO estesa");
        var data = Tlv.Parse(response.Data);
        if (data.Tag != 0x53) throw new FormatException("Risposta READ BINARY non valida.");
        return data.Value;
    }
}

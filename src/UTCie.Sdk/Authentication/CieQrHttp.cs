using System.Globalization;
using System.Text;

namespace UTCie.Sdk.Authentication;

/// <summary>Bounded HTTP/1.1 response reader for the single hybrid POST, over an already authenticated TLS stream.</summary>
internal static class CieQrHttp
{
    internal static string ReadResponse(Stream stream)
    {
        int headerBytes = 0;
        string Line()
        {
            var bytes = new List<byte>();
            while (true)
            {
                int value = stream.ReadByte();
                if (value < 0 || ++headerBytes > 16384) throw Invalid();
                if (value == '\r')
                {
                    if (stream.ReadByte() != '\n' || ++headerBytes > 16384) throw Invalid();
                    return Encoding.ASCII.GetString(bytes.ToArray());
                }
                if (value < 32 || value > 126) throw Invalid();
                bytes.Add((byte)value);
            }
        }
        var status = Line().Split(' ');
        if (status.Length < 2 || status[0] is not ("HTTP/1.1" or "HTTP/1.0") || status[1] != "200")
            throw new CieQrException("Il servizio CIE ha rifiutato la richiesta. Avvia un nuovo accesso dal sito.");
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string line;
        while ((line = Line()).Length != 0)
        {
            int colon = line.IndexOf(':');
            if (colon <= 0) throw Invalid();
            string key = line[..colon], value = line[(colon + 1)..].Trim();
            if (!headers.TryAdd(key, value) && key.ToLowerInvariant() is "content-length" or "transfer-encoding" or "content-encoding") throw Invalid();
        }
        if (headers.TryGetValue("Content-Encoding", out var encoding) && encoding != "identity") throw Invalid();
        using var body = new MemoryStream();
        void Read(int count)
        {
            if (count < 0 || count > 4096 - body.Length) throw Invalid();
            byte[] buffer = new byte[count];
            stream.ReadExactly(buffer);
            body.Write(buffer);
        }
        if (headers.TryGetValue("Transfer-Encoding", out var transfer))
        {
            if (!transfer.Equals("chunked", StringComparison.OrdinalIgnoreCase) || headers.ContainsKey("Content-Length")) throw Invalid();
            while (true)
            {
                var sizeText = Line().Split(';')[0];
                if (!int.TryParse(sizeText, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out int size) || size < 0) throw Invalid();
                if (size == 0)
                {
                    while (Line().Length != 0) { }
                    break;
                }
                Read(size);
                if (Line().Length != 0) throw Invalid();
            }
        }
        else if (headers.TryGetValue("Content-Length", out var length))
        {
            if (!int.TryParse(length, NumberStyles.None, CultureInfo.InvariantCulture, out int count)) throw Invalid();
            Read(count);
        }
        else
        {
            int value;
            while ((value = stream.ReadByte()) >= 0)
            {
                if (body.Length >= 4096) throw Invalid();
                body.WriteByte((byte)value);
            }
        }
        try { return new UTF8Encoding(false, true).GetString(body.ToArray()); }
        catch (DecoderFallbackException) { throw Invalid(); }
    }

    private static CieQrException Invalid() => new("Risposta del servizio CIE non valida.");
}

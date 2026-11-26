using SkiaSharp;
using UTCie.Sdk.Authentication;

namespace UTCIEID.App;

internal static class QrImageReader
{
    public static async Task<string> ReadAsync(Stream source)
    {
        using var data = new MemoryStream();
        byte[] buffer = new byte[8192];
        int count;
        while ((count = await source.ReadAsync(buffer)) > 0)
        {
            if (data.Length + count > 8 * 1024 * 1024) throw new ArgumentException("Immagine QR troppo grande.");
            data.Write(buffer, 0, count);
        }
        data.Position = 0;
        using var codec = SKCodec.Create(data) ?? throw new ArgumentException("Formato immagine non riconosciuto.");
        var info = codec.Info;
        if (codec.EncodedFormat is not (SKEncodedImageFormat.Png or SKEncodedImageFormat.Jpeg) ||
            info.Width is < 1 or > 4096 || info.Height is < 1 or > 4096)
            throw new ArgumentException("Formato o dimensioni immagine QR non validi.");
        using var bitmap = new SKBitmap(new SKImageInfo(info.Width, info.Height, SKColorType.Bgra8888, SKAlphaType.Opaque));
        if (codec.GetPixels(bitmap.Info, bitmap.GetPixels()) != SKCodecResult.Success)
            throw new ArgumentException("Immagine QR incompleta.");
        return CieQrDecoder.DecodeBgra(bitmap.Bytes, info.Width, info.Height);
    }
}

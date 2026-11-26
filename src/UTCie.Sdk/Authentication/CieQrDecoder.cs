using ZXing;
using ZXing.Common;

namespace UTCie.Sdk.Authentication;

public static class CieQrDecoder
{
    public static string? TryDecodeLuminance(byte[] pixels, int width, int height)
    {
        if (width is < 1 or > 4096 || height is < 1 or > 4096 || pixels.Length != checked(width * height))
            throw new ArgumentException("Dimensioni del fotogramma QR non valide.");
        var reader = CreateReader();
        var results = reader.DecodeMultiple(new PlanarYUVLuminanceSource(pixels, width, height, 0, 0, width, height, false));
        return results is { Length: 1 } && results[0].Text.Length <= 8192 ? results[0].Text : null;
    }

    public static string DecodeBgra(byte[] pixels, int width, int height)
    {
        if (width is < 1 or > 4096 || height is < 1 or > 4096 || pixels.Length != checked(width * height * 4))
            throw new ArgumentException("Dimensioni dell'immagine QR non valide.");
        var reader = CreateReader();
        var results = reader.DecodeMultiple(new RGBLuminanceSource(pixels, width, height, RGBLuminanceSource.BitmapFormat.BGRA32));
        if (results is not { Length: 1 } || results[0].Text.Length > 8192)
            throw new ArgumentException("L'immagine deve contenere un solo QR leggibile.");
        return results[0].Text;
    }

    private static BarcodeReaderGeneric CreateReader() => new()
    {
        AutoRotate = true,
        Options = new DecodingOptions { PossibleFormats = [BarcodeFormat.QR_CODE], TryHarder = true, TryInverted = true }
    };
}

public sealed class QrScanException(string message) : Exception(message);

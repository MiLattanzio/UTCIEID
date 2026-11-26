using System.Globalization;
using System.Runtime.InteropServices;
using Avalonia;
using Avalonia.Data.Converters;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using UTCie.Sdk.Card;

namespace UTCIEID.App;

public sealed class PortraitConverter : IValueConverter
{
    private Bitmap? _current;
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        _current?.Dispose(); _current = null;
        if (value is not IcaoDocument document) return null;
        try
        {
            if (document.PortraitMimeType == "image/jpeg")
            {
                using var stream = new MemoryStream(document.Portrait, false);
                return _current = Bitmap.DecodeToWidth(stream, 480);
            }
            IntPtr pixels = IntPtr.Zero;
            try
            {
                if (Decode(document.Portrait, (nuint)document.Portrait.Length, out pixels, out int width, out int height) == 0) return null;
                return _current = new Bitmap(PixelFormat.Rgba8888, AlphaFormat.Opaque, pixels, new PixelSize(width, height), new Vector(96, 96), width * 4);
            }
            finally { if (pixels != IntPtr.Zero) Free(pixels); }
        }
        catch { return null; }
    }
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
    [DllImport("libutcieid-portrait.so", EntryPoint = "utcieid_decode_portrait", CallingConvention = CallingConvention.Cdecl)]
    private static extern int Decode(byte[] input, nuint length, out IntPtr pixels, out int width, out int height);
    [DllImport("libutcieid-portrait.so", EntryPoint = "utcieid_free_portrait", CallingConvention = CallingConvention.Cdecl)]
    private static extern void Free(IntPtr pixels);
}

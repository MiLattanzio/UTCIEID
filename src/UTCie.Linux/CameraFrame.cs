using System.Buffers.Binary;

namespace UTCie.Linux;

public sealed record CameraFrame(int Width, int Height, int Rotation, byte[] Luminance)
{
    internal static async Task<CameraFrame> ReadAsync(Stream stream, CancellationToken token)
    {
        byte[] header = new byte[20];
        await stream.ReadExactlyAsync(header, token).ConfigureAwait(false);
        int Read(int position) => BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(position, 4));
        int w = Read(4), h = Read(8), angle = Read(12), length = Read(16);
        if (Read(0) != 0x314D4143 || w is < 1 or > 1280 || h is < 1 or > 960 ||
            angle is not (0 or 90 or 180 or 270) || length != checked(w * h))
            throw new InvalidDataException("Fotogramma fotocamera non valido.");
        byte[] pixels = new byte[length];
        await stream.ReadExactlyAsync(pixels, token).ConfigureAwait(false);
        return new(w, h, angle, pixels);
    }

    public (int Width, int Height, byte[] Pixels) ToBgra()
    {
        if (Width is < 1 or > 1280 || Height is < 1 or > 960 || Luminance.Length != checked(Width * Height) ||
            Rotation is not (0 or 90 or 180 or 270)) throw new InvalidDataException("Fotogramma fotocamera non valido.");
        int w = Rotation % 180 == 0 ? Width : Height, h = Rotation % 180 == 0 ? Height : Width;
        byte[] pixels = new byte[w * h * 4];
        for (int y = 0; y < Height; y++)
        for (int x = 0; x < Width; x++)
        {
            (int tx, int ty) = Rotation switch
            {
                90 => (Height - y - 1, x), 180 => (Width - x - 1, Height - y - 1),
                270 => (y, Width - x - 1), _ => (x, y)
            };
            int i = (ty * w + tx) * 4;
            byte value = Luminance[y * Width + x];
            pixels[i] = pixels[i + 1] = pixels[i + 2] = value; pixels[i + 3] = 255;
        }
        return (w, h, pixels);
    }
}

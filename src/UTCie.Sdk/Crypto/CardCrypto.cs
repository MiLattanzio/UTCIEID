// Port of IPZS cieid-android-sdk Algoritmi/RSA/AppUtil (BSD-3-Clause).
using System.Numerics;
using System.Security.Cryptography;
using UTCie.Sdk.Card;

namespace UTCie.Sdk.Crypto;

internal static class CardCrypto
{
    public static byte[] Pad(ReadOnlySpan<byte> data)
    {
        var result = new byte[(data.Length / 8 + 1) * 8];
        data.CopyTo(result);
        result[data.Length] = 0x80;
        return result;
    }

    public static byte[] Unpad(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0 || data.Length % 8 != 0) throw new CardProtocolException("Padding SM non valido.");
        int i = data.Length - 1;
        while (i >= Math.Max(0, data.Length - 8) && data[i] == 0) i--;
        if (i < Math.Max(0, data.Length - 8) || data[i] != 0x80) throw new CardProtocolException("Padding SM non valido.");
        return data[..i].ToArray();
    }

    public static byte[] Des(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, bool encrypt)
    {
        using SymmetricAlgorithm algorithm = key.Length == 8 ? DES.Create() : TripleDES.Create();
        byte[] expanded = key.Length == 16 ? [..key, ..key[..8]] : key.ToArray();
        try
        {
            // Expand K1,K2 to K1,K2,K1: OpenSSL providers may reject a 16-byte DES-EDE3 key.
            algorithm.Key = expanded;
            return encrypt ? algorithm.EncryptCbc(data, new byte[8], PaddingMode.None)
                : algorithm.DecryptCbc(data, new byte[8], PaddingMode.None);
        }
        finally { CryptographicOperations.ZeroMemory(expanded); }
    }

    public static byte[] Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> padded)
    {
        if (key.Length != 16 || padded.Length == 0 || padded.Length % 8 != 0) throw new ArgumentException("MAC input non valido.");
        var mid = Des(key[..8], padded, true);
        return Des(key[..8], Des(key[8..], mid.AsSpan(mid.Length - 8), false), true);
    }

    public static byte[] ModPow(ReadOnlySpan<byte> value, ReadOnlySpan<byte> exponent, ReadOnlySpan<byte> modulus)
    {
        var m = new BigInteger(modulus, isUnsigned: true, isBigEndian: true);
        var v = new BigInteger(value, isUnsigned: true, isBigEndian: true);
        var e = new BigInteger(exponent, isUnsigned: true, isBigEndian: true);
        if (m <= 1 || v >= m || e <= 0 || modulus.Length > 512) throw new CardProtocolException("Parametri RSA/DH non validi.");
        var raw = BigInteger.ModPow(v, e, m).ToByteArray(isUnsigned: true, isBigEndian: true);
        var result = new byte[modulus.Length];
        raw.CopyTo(result, result.Length - raw.Length);
        return result;
    }

    public static byte[] RandomExponent(ReadOnlySpan<byte> order)
    {
        var q = new BigInteger(order, true, true);
        if (q <= 3 || order.Length > 512) throw new CardProtocolException("Ordine DH non valido.");
        byte[] result = new byte[order.Length];
        int leading = BitOperations.LeadingZeroCount((uint)order[0]) - 24;
        do
        {
            RandomNumberGenerator.Fill(result);
            result[0] &= (byte)(255 >> leading);
        } while (new BigInteger(result, true, true) < 2 || new BigInteger(result, true, true) >= q);
        return result;
    }

    public static void Increment(Span<byte> counter)
    {
        for (int i = counter.Length - 1; i >= 0; i--)
            if (++counter[i] != 0) return;
        throw new CardProtocolException("Contatore SM esaurito.");
    }
}

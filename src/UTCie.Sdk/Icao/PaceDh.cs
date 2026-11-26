using System.Security.Cryptography;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace UTCie.Sdk.Icao;

/// <summary>ICAO 9303 Part 11 DH Generic Mapping, using RFC 5114 subgroups.</summary>
internal static class PaceDh
{
    internal static SecureMessaging Authenticate(EmrtdSession session, byte[] passwordSeed, byte passwordReference, PaceInfo info,
        Func<BigInteger, BigInteger> mappingPrivateKey, Func<BigInteger, BigInteger> agreementPrivateKey)
    {
        var group = DhGroup.Standard[info.ParameterId!.Value];
        byte[] oid = Pace.OidContent(info.Oid);
        int width = (group.P.BitLength + 7) / 8;
        session.Send(new(0, 0x22, 0xc1, 0xa4, [..Tlv.Encode(0x80, oid), ..Tlv.Encode(0x83, [passwordReference]), ..Tlv.Encode(0x84, [(byte)info.ParameterId.Value])]))
            .EnsureSuccess("PACE DH MSE:Set AT");
        byte[] key = Crypto.Kdf(passwordSeed, 3, info.Cipher);
        byte[] nonce;
        try { nonce = Crypto.Decrypt(info.Cipher, key, Pace.GeneralAuthenticate(session, [0x7c, 0], 0x80, false), new byte[Crypto.BlockSize(info.Cipher)]); }
        finally { CryptographicOperations.ZeroMemory(key); }
        var s = new BigInteger(1, nonce);
        CryptographicOperations.ZeroMemory(nonce);

        BigInteger x1 = mappingPrivateKey(group.Q);
        BigInteger public1 = group.G.ModPow(x1, group.P);
        BigInteger peer1 = DecodePublic(group, Pace.GeneralAuthenticate(session, Tlv.Encode(0x7c, Tlv.Encode(0x81, Encode(public1))), 0x82, false));
        BigInteger h = peer1.ModPow(x1, group.P);
        BigInteger mapped = group.G.ModPow(s, group.P).Multiply(h).Mod(group.P);
        if (mapped.Equals(BigInteger.One)) throw new CryptographicException("PACE DH: invalid mapped generator.");

        BigInteger x2 = agreementPrivateKey(group.Q);
        BigInteger public2 = mapped.ModPow(x2, group.P);
        BigInteger peer2 = DecodePublic(group, Pace.GeneralAuthenticate(session, Tlv.Encode(0x7c, Tlv.Encode(0x83, Encode(public2))), 0x84, false));
        if (peer2.Equals(public2)) throw new CryptographicException("PACE DH: reflected public key.");
        byte[] secret = Encode(peer2.ModPow(x2, group.P));
        byte[] enc = Crypto.Kdf(secret, 1, info.Cipher), mac = Crypto.Kdf(secret, 2, info.Cipher);
        CryptographicOperations.ZeroMemory(secret);
        try
        {
            byte[] ours = Token(info.Cipher, mac, oid, Encode(peer2));
            var response = Pace.GeneralAuthenticateRaw(session, Tlv.Encode(0x7c, Tlv.Encode(0x85, ours)), true).EnsureSuccess("PACE DH autenticazione del CAN");
            byte[] theirs = Pace.DynamicObject(response, 0x86);
            if (!CryptographicOperations.FixedTimeEquals(theirs, Token(info.Cipher, mac, oid, Encode(public2)))) throw new CryptographicException("PACE DH: invalid authentication token.");
            return new(info.Cipher, enc, mac, new byte[Crypto.BlockSize(info.Cipher)]);
        }
        finally { CryptographicOperations.ZeroMemory(enc); CryptographicOperations.ZeroMemory(mac); }

        byte[] Encode(BigInteger value) => BigIntegers.AsUnsignedByteArray(width, value);
    }

    internal static BigInteger DecodePublic(DhGroup group, byte[] encoded)
    {
        if (encoded.Length == 0 || encoded.Length > (group.P.BitLength + 7) / 8) throw new CryptographicException("PACE DH: invalid public key length.");
        var y = new BigInteger(1, encoded);
        if (y.CompareTo(BigInteger.One) <= 0 || y.CompareTo(group.P.Subtract(BigInteger.One)) >= 0 || !y.ModPow(group.Q, group.P).Equals(BigInteger.One))
            throw new CryptographicException("PACE DH: public key outside the prime-order subgroup.");
        return y;
    }

    internal static byte[] Token(SmCipher cipher, byte[] mac, byte[] oid, byte[] publicKey)
    {
        byte[] data = Tlv.Encode(0x7f49, [..Tlv.Encode(0x06, oid), ..Tlv.Encode(0x84, publicKey)]);
        return Crypto.Mac(cipher, mac, cipher == SmCipher.TripleDes ? Crypto.Pad(data, 8) : data);
    }
}

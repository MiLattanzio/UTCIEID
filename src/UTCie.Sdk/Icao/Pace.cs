// Adapted from emrtd-dotnet, Copyright (c) 2026 Chamnan Nop, MIT. See licenses/emrtd-dotnet.txt.
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace UTCie.Sdk.Icao;

internal enum PaceMapping { GenericMapping, IntegratedMapping, ChipAuthenticationMapping }

/// <summary>A PACEInfo entry from EF.CardAccess (ICAO 9303 Part 11 §9.2.1).</summary>
internal sealed record PaceInfo(string Oid, int Version, int? ParameterId)
{
    public const string IdPace = "0.4.0.127.0.7.2.2.4";

    private string[] Arcs => Oid[(IdPace.Length + 1)..].Split('.');

    public bool IsEcdh => Arcs[0] is "2" or "4" or "6";

    public PaceMapping Mapping => Arcs[0] switch
    {
        "1" or "2" => PaceMapping.GenericMapping,
        "3" or "4" => PaceMapping.IntegratedMapping,
        _ => PaceMapping.ChipAuthenticationMapping,
    };

    public SmCipher Cipher => Arcs[1] switch
    {
        "1" => SmCipher.TripleDes,
        "2" => SmCipher.Aes128,
        "3" => SmCipher.Aes192,
        _ => SmCipher.Aes256,
    };

    /// <summary>
    /// Implemented: DH and ECDH with Generic Mapping on standardized domain parameters.
    /// </summary>
    public bool IsSupported =>
        Version == 2 && Arcs.Length == 2 && Arcs[1] is "1" or "2" or "3" or "4" && ParameterId is int id &&
        (Arcs[0] == "2" && Pace.CurveName(id) is not null || Arcs[0] == "1" && id is >= 0 and <= 2);

    public override string ToString() =>
        $"PACE-{(IsEcdh ? "ECDH" : "DH")}-{Mapping switch { PaceMapping.GenericMapping => "GM", PaceMapping.IntegratedMapping => "IM", _ => "CAM" }}" +
        $"-{Cipher} ({(ParameterId is int p ? Pace.CurveName(p) ?? $"parameter {p}" : "no parameter id")})";

    public static IReadOnlyList<PaceInfo> ParseCardAccess(byte[] cardAccess)
    {
        var result = new List<PaceInfo>();
        foreach (var entry in Asn1Set.GetInstance(Asn1Object.FromByteArray(cardAccess)))
        {
            if (entry is not Asn1Sequence { Count: >= 2 } info || info[0] is not DerObjectIdentifier oid) continue;
            string id = oid.Id;
            // PACEInfo OIDs are id-PACE.<mapping>.<cipher>; skip other SecurityInfos (CA, TA, domain parameters, ...).
            if (!id.StartsWith(IdPace + ".", StringComparison.Ordinal) || id.Count(c => c == '.') != IdPace.Count(c => c == '.') + 2)
                continue;

            int version = DerInteger.GetInstance(info[1]).IntValueExact;
            int? parameterId = info.Count > 2 && info[2] is DerInteger p ? p.IntValueExact : null;
            result.Add(new PaceInfo(id, version, parameterId));
        }
        return result;
    }
}

/// <summary>
/// PACE v2 (ICAO 9303 Part 11 §4.4) with the MRZ as password, ECDH generic mapping.
/// Runs before the eMRTD applet is selected; the returned secure messaging session starts with SSC = 0.
/// </summary>
internal static class Pace
{
    public static string? CurveName(int parameterId) => parameterId switch
    {
        8 => "secp192r1",
        9 => "brainpoolP192r1",
        10 => "secp224r1",
        11 => "brainpoolP224r1",
        12 => "secp256r1",
        13 => "brainpoolP256r1",
        14 => "brainpoolP320r1",
        15 => "secp384r1",
        16 => "brainpoolP384r1",
        17 => "brainpoolP512r1",
        18 => "secp521r1",
        _ => null,
    };

    public static SecureMessaging Authenticate(EmrtdSession session, MrzKey key, PaceInfo info)
    {
        var random = new SecureRandom();
        return Authenticate(session, key.Hash(), 1, info, n => RandomScalar(n, random), n => RandomScalar(n, random));
    }

    public static SecureMessaging AuthenticateCan(EmrtdSession session, ReadOnlySpan<char> can, PaceInfo info)
    {
        if (can.Length != 6 || can.ContainsAnyExceptInRange('0', '9')) throw new ArgumentException("Il CAN deve contenere 6 cifre.");
        var random = new SecureRandom();
        byte[] seed = System.Text.Encoding.ASCII.GetBytes(can.ToArray());
        try { return Authenticate(session, seed, 2, info, n => RandomScalar(n, random), n => RandomScalar(n, random)); }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }

    /// <summary>Overload with injectable private keys so the ICAO worked example (Appendix G) can be replayed.</summary>
    internal static SecureMessaging Authenticate(EmrtdSession session, byte[] passwordSeed, byte passwordReference, PaceInfo info,
        Func<BigInteger, BigInteger> mappingPrivateKey, Func<BigInteger, BigInteger> agreementPrivateKey)
    {
        if (!info.IsSupported) throw new NotSupportedException($"{info} is not supported.");

        if (!info.IsEcdh) return PaceDh.Authenticate(session, passwordSeed, passwordReference, info, mappingPrivateKey, agreementPrivateKey);

        X9ECParameters curve = ECNamedCurveTable.GetByName(CurveName(info.ParameterId!.Value));
        var domain = new ECDomainParameters(curve);
        SmCipher cipher = info.Cipher;
        byte[] oid = OidContent(info.Oid);

        // MSE:Set AT — protocol OID, password = MRZ (01), standardized domain parameters.
        session.Send(new CommandApdu(0x00, 0x22, 0xC1, 0xA4,
            [.. Tlv.Encode(0x80, oid), .. Tlv.Encode(0x83, [passwordReference]), .. Tlv.Encode(0x84, [(byte)info.ParameterId.Value])]))
            .EnsureSuccess("PACE MSE:Set AT");

        // 1. Encrypted nonce: s = D(Kπ, z).
        byte[] kPi = Crypto.Kdf(passwordSeed, Crypto.KdfPace, cipher);
        byte[] z = GeneralAuthenticate(session, [0x7C, 0x00], 0x80, last: false);
        byte[] nonce = Crypto.Decrypt(cipher, kPi, z, new byte[Crypto.BlockSize(cipher)]);
        CryptographicOperations.ZeroMemory(kPi);
        var s = new BigInteger(1, nonce);
        CryptographicOperations.ZeroMemory(nonce);

        // 2. Generic mapping: G~ = s·G + H, where H is an ECDH shared point.
        BigInteger mapPrivate = mappingPrivateKey(domain.N);
        ECPoint mapPublic = domain.G.Multiply(mapPrivate).Normalize();
        ECPoint chipMapPublic = DecodePoint(curve, GeneralAuthenticate(session, Tlv.Encode(0x7C, Tlv.Encode(0x81, mapPublic.GetEncoded(false))), 0x82, last: false));
        ECPoint h = chipMapPublic.Multiply(mapPrivate).Normalize();
        if (h.IsInfinity) throw new CryptographicException("PACE mapping produced the point at infinity.");
        ECPoint mappedG = domain.G.Multiply(s).Add(h).Normalize();
        if (mappedG.IsInfinity) throw new CryptographicException("PACE: invalid mapped generator.");

        // 3. Key agreement on the mapped generator.
        BigInteger ephemeralPrivate = agreementPrivateKey(domain.N);
        ECPoint ephemeralPublic = mappedG.Multiply(ephemeralPrivate).Normalize();
        ECPoint chipEphemeralPublic = DecodePoint(curve, GeneralAuthenticate(session, Tlv.Encode(0x7C, Tlv.Encode(0x83, ephemeralPublic.GetEncoded(false))), 0x84, last: false));
        if (chipEphemeralPublic.Equals(ephemeralPublic)) throw new CryptographicException("PACE: chip reflected our public key.");

        ECPoint shared = chipEphemeralPublic.Multiply(ephemeralPrivate).Normalize();
        if (shared.IsInfinity) throw new CryptographicException("PACE: invalid shared point.");
        byte[] sharedSecret = BigIntegers.AsUnsignedByteArray((curve.Curve.FieldSize + 7) / 8, shared.AffineXCoord.ToBigInteger());
        byte[] ksEnc = Crypto.Kdf(sharedSecret, Crypto.KdfEnc, cipher);
        byte[] ksMac = Crypto.Kdf(sharedSecret, Crypto.KdfMac, cipher);
        CryptographicOperations.ZeroMemory(sharedSecret);
        try
        {

        // 4. Mutual authentication: exchange MACs over each other's ephemeral public key.
        byte[] ourToken = AuthenticationToken(cipher, ksMac, oid, chipEphemeralPublic);
        var final = GeneralAuthenticateRaw(session, Tlv.Encode(0x7C, Tlv.Encode(0x85, ourToken)), last: true);
        if (final.SW == 0x6300)
            throw new CardException(final.SW, "PACE rifiutato: controlla il CAN stampato sulla carta");
        byte[] chipToken = DynamicObject(final.EnsureSuccess("PACE mutual authentication"), 0x86);
        if (!CryptographicOperations.FixedTimeEquals(chipToken, AuthenticationToken(cipher, ksMac, oid, ephemeralPublic)))
            throw new CryptographicException("PACE: chip authentication token is invalid.");

        return new SecureMessaging(cipher, ksEnc, ksMac, new byte[Crypto.BlockSize(cipher)]);
        }
        finally { CryptographicOperations.ZeroMemory(ksEnc); CryptographicOperations.ZeroMemory(ksMac); }
    }

    /// <summary>T = MAC(KSmac, 7F49 { 06 OID, 86 public point }). 3DES uses retail MAC with padding, AES uses CMAC.</summary>
    internal static byte[] AuthenticationToken(SmCipher cipher, byte[] ksMac, byte[] oidContent, ECPoint publicKey)
    {
        byte[] dataObject = Tlv.Encode(0x7F49, [.. Tlv.Encode(0x06, oidContent), .. Tlv.Encode(0x86, publicKey.GetEncoded(false))]);
        return Crypto.Mac(cipher, ksMac, cipher == SmCipher.TripleDes ? Crypto.Pad(dataObject, 8) : dataObject);
    }

    internal static byte[] OidContent(string oid) => new DerObjectIdentifier(oid).GetEncoded()[2..];

    internal static byte[] GeneralAuthenticate(EmrtdSession session, byte[] data, int responseTag, bool last) =>
        DynamicObject(GeneralAuthenticateRaw(session, data, last).EnsureSuccess("PACE General Authenticate"), responseTag);

    // Steps 1-3 use command chaining (CLA 10); the final step uses CLA 00.
    internal static ResponseApdu GeneralAuthenticateRaw(EmrtdSession session, byte[] data, bool last) =>
        session.Send(new CommandApdu(last ? (byte)0x00 : (byte)0x10, 0x86, 0x00, 0x00, data, Ne: data.Length > 255 ? 65536 : 256));

    internal static byte[] DynamicObject(ResponseApdu response, int tag)
    {
        var template = Tlv.Parse(response.Data);
        if (template.Tag != 0x7C) throw new CardException(response.SW, "PACE: response is not a dynamic authentication data object");
        return template.Children.FirstOrDefault(c => c.Tag == tag)?.Value
            ?? throw new CardException(response.SW, $"PACE: response is missing tag {tag:X2}");
    }

    private static ECPoint DecodePoint(X9ECParameters curve, byte[] encoded)
    {
        ECPoint point = curve.Curve.DecodePoint(encoded).Normalize();
        if (point.IsInfinity || !point.IsValid()) throw new CryptographicException("PACE: chip sent an invalid EC point.");
        return point;
    }

    private static BigInteger RandomScalar(BigInteger n, SecureRandom random) =>
        BigIntegers.CreateRandomInRange(BigInteger.One, n.Subtract(BigInteger.One), random);
}

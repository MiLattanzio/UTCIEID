using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;

namespace UTCie.Sdk.Card;

/// <summary>Public data read from one card. Never contains a PIN or a private key.</summary>
public sealed record CardProfile(string ServiceIdHash, byte[] CertificateDer, DateTimeOffset SavedAt, IcaoDocument? Document = null)
{
    public CertificateDetails GetCertificateDetails()
    {
        using var cert = X509CertificateLoader.LoadCertificate(CertificateDer);
        var name = X509Name.GetInstance(Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(cert.SubjectName.RawData));
        string Value(Org.BouncyCastle.Asn1.DerObjectIdentifier oid) => string.Join(" ", name.GetValueList(oid));
        // X.500: givenName = 2.5.4.42, surname = 2.5.4.4. The 2015 CIE PDF swaps these OID labels.
        string serial = Value(X509Name.SerialNumber);
        string common = Value(X509Name.CN);
        return new(Value(X509Name.GivenName), Value(X509Name.Surname),
            serial.StartsWith("IDCIT-", StringComparison.Ordinal) ? serial[6..] : serial,
            common.Split('/')[0], Value(X509Name.C), cert.Subject, cert.Issuer,
            cert.NotBefore, cert.NotAfter, cert.SerialNumber, Convert.ToHexString(SHA256.HashData(CertificateDer)));
    }

    public void Validate()
    {
        if (ServiceIdHash.Length != 64 || ServiceIdHash.Any(c => !Uri.IsHexDigit(c)) || CertificateDer.Length is < 1 or > 32768)
            throw new CardProtocolException("Profilo della carta non valido.");
        _ = GetCertificateDetails();
        if (Document is not null && (Document.Portrait.Length is < 1 or > 1048576 || Document.Sod.Length > 65536 || Document.Mrz.Length != 90))
            throw new CardProtocolException("Dati del documento non validi.");
    }
}

public sealed record CertificateDetails(string GivenName, string Surname, string DocumentNumber, string FiscalCode,
    string Country, string Subject, string Issuer, DateTime NotBefore, DateTime NotAfter, string SerialNumber, string Sha256);

public sealed record IcaoDocument(string GivenName, string Surname, string DocumentNumber, string DateOfBirth,
    string DateOfExpiry, string Nationality, string Sex, string Mrz, byte[] Portrait, string PortraitMimeType,
    byte[] Sod, DateTimeOffset ReadAt);

public interface ICardProfileStore
{
    Task<CardProfile?> GetProfileAsync(RegisteredCard card, CancellationToken token = default);
    Task SaveProfileAsync(CardProfile profile, CancellationToken token = default);
    Task DeleteProfileAsync(RegisteredCard card, CancellationToken token = default);
}

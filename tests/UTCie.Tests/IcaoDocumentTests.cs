using System.Security.Cryptography;
using NUnit.Framework;
using UTCie.Sdk.Icao;

namespace UTCie.Tests.Icao;

public class IcaoDocumentTests
{
    [Test] public async Task CardAccessAndPaceMustPrecedeAnyIasSelection()
    {
        // Real CIE: selecting IAS first hides CardAccess even after SELECT MF (SW 6A82).
        var transport = new UTCie.Tests.TranscriptTransport(
            ("00A4000C023F00", "9000"),
            ("00A4020C02011C", "9000"),
            ("00B0000008", "31143012060A04009000"),
            ("00B000080E", "7F000702020401010201020201029000"),
            ("0022C1A412800A04007F00070202040101830102840102", "6982"));
        var reader = new IcaoDocumentReader(new UTCie.Tests.FakeReader(transport));
        var error = Assert.ThrowsAsync<UTCie.Sdk.Card.CardException>(async () => await reader.ReadAsync(new(new string('1',64)), "CA12345AA", "123456".AsMemory()));
        Assert.That(error!.Message, Does.Contain("MSE:Set AT"));
        await Task.CompletedTask;
    }

    [TestCase(1)]
    [TestCase(2)]
    [TestCase(3)]
    [TestCase(4)]
    public void FullCanSessionReadsSignedDocumentOverEverySupportedCipher(int algorithm)
    {
        var document = new TestDocument();
        var chip = new ChipSimulator("123456", document.Files, TestDocument.CardAccess($"0.4.0.127.0.7.2.2.4.2.{algorithm}", 13));
        using var session = new EmrtdSession(chip.Transmit);
        session.SelectMasterFile();
        var pace = PaceInfo.ParseCardAccess(session.ReadFile(0x011c)).Single();
        session.StartSecureMessaging(Pace.AuthenticateCan(session, "123456", pace));
        session.SelectApplet();
        var dg1 = session.ReadFile(0x0101);
        var dg2 = session.ReadFile(0x0102);
        var sod = session.ReadFile(0x011d);
        IcaoDocumentReader.VerifySignedData(sod, dg1, dg2);
        Assert.That(IcaoDocumentReader.ParseDocument(dg1, dg2, sod).Portrait, Is.EqualTo(document.FaceJpeg));
        Assert.That(chip.Log.Any(l => l.StartsWith("20 ")), Is.False);
    }

    [Test] public void ReadsTd1AndPortraitAndVerifiesSignedHashes()
    {
        var card = new TestDocument();
        IcaoDocumentReader.VerifySignedData(card.Files[0x011d], card.DataGroups[1], card.DataGroups[2]);
        var document = IcaoDocumentReader.ParseDocument(card.DataGroups[1], card.DataGroups[2], card.Files[0x011d]);
        Assert.That(document.GivenName, Is.EqualTo("ANNA MARIA"));
        Assert.That(document.Surname, Is.EqualTo("ERIKSSON"));
        Assert.That(document.DocumentNumber, Is.EqualTo("D23145890"));
        Assert.That(document.DateOfBirth, Is.EqualTo("740812"));
        Assert.That(document.Portrait, Is.EqualTo(card.FaceJpeg));
        card.DataGroups[2][^5] ^= 1;
        Assert.Throws<CryptographicException>(() => IcaoDocumentReader.VerifySignedData(card.Files[0x011d], card.DataGroups[1], card.DataGroups[2]));
    }

    [Test] public void CanSelectsPasswordReferenceTwoAndNeverVerifiesPin()
    {
        byte[]? command = null;
        using var session = new EmrtdSession(apdu => { command = apdu; return [0x6a, 0x80]; });
        Assert.Throws<CardException>(() => Pace.AuthenticateCan(session, "123456", new PaceInfo("0.4.0.127.0.7.2.2.4.2.4", 2, 13)));
        Assert.That(Convert.ToHexString(command!), Is.EqualTo("0022C1A412800A04007F0007020204020483010284010D"));
    }

    [TestCase("0.4.0.127.0.7.2.2.4.2.99", 2)]
    [TestCase("0.4.0.127.0.7.2.2.4.6.4", 2)]
    [TestCase("0.4.0.127.0.7.2.2.4.2.4", 1)]
    public void UnsupportedPaceParametersDoNotSilentlySelectAnotherAlgorithm(string oid, int version)
        => Assert.That(new PaceInfo(oid, version, 13).IsSupported, Is.False);

    [TestCase("9F8181818100")]
    [TestCase("758400FFFFFF")]
    [TestCase("7580")]
    [TestCase("750000")]
    public void MalformedTlvFailsWithBounds(string hex) => Assert.Throws<FormatException>(() => Tlv.Parse(Convert.FromHexString(hex)));

    [Test] public void SecureMessagingRejectsUnauthenticatedStatusAndCannotBeReused()
    {
        using var sm = new SecureMessaging(SmCipher.Aes256, new byte[32], new byte[32], new byte[16]);
        Assert.Throws<CryptographicException>(() => sm.Unwrap([0x90, 0]));
        Assert.Throws<ObjectDisposedException>(() => sm.Wrap(new(0, 0xb0, 0, 0, Ne: 8)));
    }

    [Test] public void FingerprintAndIrisFilesCannotBeSelected()
    {
        using var session = new EmrtdSession(_ => throw new AssertionException("Nessun comando NFC atteso."));
        Assert.Throws<ArgumentOutOfRangeException>(() => session.ReadFile(0x0103));
        Assert.Throws<ArgumentOutOfRangeException>(() => session.ReadFile(0x0104));
    }
}

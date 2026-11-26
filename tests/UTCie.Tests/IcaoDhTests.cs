using System.Security.Cryptography;
using NUnit.Framework;
using Org.BouncyCastle.Math;
using UTCie.Sdk.Icao;
namespace UTCie.Tests.Icao;

public class IcaoDhTests
{
    // ICAO Doc 9303 Part 11, seventh edition, Appendix G.2. Independent published outputs.
    [Test] public void DhGenericMappingMatchesIcaoWorkedExample()
    {
        int step = 0;
        using var session = new EmrtdSession(wire =>
        {
            var command = UTCie.Sdk.Card.ApduCommand.Parse(wire);
            switch (step++)
            {
                case 0:
                    Assert.That(Convert.ToHexString(command.Data), Is.EqualTo("800A04007F00070202040102830101840100"));
                    return [0x90, 0];
                case 1: return [..Tlv.Encode(0x7c, Tlv.Encode(0x80, Convert.FromHexString("854D8DF5827FA6852D1A4FA701CDDDCA"))), 0x90, 0];
                case 2:
                    Assert.That(Convert.ToHexString(Tlv.Parse(command.Data).Children.Single().Value), Is.EqualTo("23FB3749EA030D2A25B278D2A562047ADE3F01B74F17A15402CB7352CA7D2B3EB71C343DB13D1DEBCE9A3666DBCFC920B49174A602CB47965CAA73DC702489A44D41DB914DE9613DC5E98C94160551C0DF86274B9359BC0490D01B03AD54022DCB4F57FAD6322497D7A1E28D46710F461AFE710FBBBC5F8BA166F4311975EC6C"));
                    return [..Tlv.Encode(0x7c, Tlv.Encode(0x82, Convert.FromHexString("78879F57225AA8080D52ED0FC890A4B25336F699AA89A2D3A189654AF70729E623EA5738B26381E4DA19E004706FACE7B235C2DBF2F38748312F3C98C2DD4882A41947B324AA1259AC22579DB93F7085655AF30889DBB845D9E6783FE42C9F2449400306254C8AE8EE9DD812A804C0B66E8CAFC14F84D8258950A91B44126EE6"))), 0x90, 0];
                case 3:
                    Assert.That(Convert.ToHexString(Tlv.Parse(command.Data).Children.Single().Value), Is.EqualTo("907D89E2D425A178AA81AF4A7774EC8E388C115CAE67031E85EECE520BD911551B9AE4D04369F29A02626C86FBC6747CC7BC352645B6161A2A42D44EDA80A08FA8D61B76D3A154AD8A5A51786B0BC07147057871A922212C5F67F43173172236B7747D1671E6D692A3C7D40A0C3C5CE397545D015C175EB5130551EDBC2EE5D4"));
                    return [..Tlv.Encode(0x7c, Tlv.Encode(0x84, Convert.FromHexString("075693D9AE941877573E634B6E644F8E60AF17A0076B8B123D9201074D36152BD8B3A213F53820C42ADC79AB5D0AEEC3AEFB91394DA476BD97B9B14D0A65C1FC71A0E019CB08AF55E1F729005FBA7E3FA5DC41899238A250767A6D46DB974064386CD456743585F8E5D90CC8B4004B1F6D866C79CE0584E49687FF61BC29AEA1"))), 0x90, 0];
                case 4:
                    Assert.That(Convert.ToHexString(Tlv.Parse(command.Data).Children.Single().Value), Is.EqualTo("B46DD9BD4D98381F"));
                    return [..Tlv.Encode(0x7c, Tlv.Encode(0x86, Convert.FromHexString("917F37B5C0E6D8D1"))), 0x90, 0];
                default: throw new AssertionException("Unexpected command");
            }
        });
        using var sm = Pace.Authenticate(session, new MrzKey("T22000129", "640812", "101031").Hash(), 1,
            new PaceInfo("0.4.0.127.0.7.2.2.4.1.2", 2, 0),
            _ => new BigInteger("5265030F751F4AD18B08AC565FC7AC952E41618D", 16), _ => new BigInteger("89CCD99B0E8D3B1F11E1296DCA68EC53411CF2CA", 16));
        Assert.That(step, Is.EqualTo(5));
        Assert.That(sm.Ssc, Is.EqualTo(new byte[16]));
    }

    [Test] public void CieAdvertisedDhParametersAreSupportedAndSubgroupChecked()
    {
        var info = PaceInfo.ParseCardAccess(Convert.FromHexString("31143012060A04007F00070202040101020102020102")).Single();
        Assert.That(info.IsSupported, Is.True);
        Assert.That(info.IsEcdh, Is.False);
        Assert.That(info.Cipher, Is.EqualTo(SmCipher.TripleDes));
        Assert.Throws<CryptographicException>(() => PaceDh.DecodePublic(DhGroup.Standard[2], [1]));
        Assert.Throws<CryptographicException>(() => PaceDh.DecodePublic(DhGroup.Standard[2], [2]));
    }
}

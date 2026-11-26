using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using UTCie.Sdk.Card;
using CardTransport = UTCie.Sdk.Card.ICardTransport;

namespace UTCie.Sdk.Icao;

public sealed class IcaoDocumentReader(ICardReader reader)
{
    public async Task<IcaoDocument> ReadAsync(RegisteredCard registered, string expectedDocumentNumber, ReadOnlyMemory<char> can,
        IProgress<CieProgress>? progress = null, CancellationToken token = default)
    {
        if (can.Length != 6 || can.Span.ContainsAnyExceptInRange('0', '9')) throw new ArgumentException("Il CAN deve contenere 6 cifre.");
        progress?.Report(CieProgress.WaitingForCard);
        await using var transport = await reader.WaitForCardAsync(token).ConfigureAwait(false);
        progress?.Report(CieProgress.CardDetected);
        IcaoDocument result;
        try
        {
            result = await Task.Run(() =>
            {
                using var session = new EmrtdSession(command =>
                {
                    token.ThrowIfCancellationRequested();
                    // This path has no access to the stored PIN and must never verify one.
                    if (command[1] == 0x20) throw new InvalidOperationException("VERIFY vietato nella lettura ICAO.");
                    return transport.TransceiveAsync(command, token).AsTask().GetAwaiter().GetResult();
                });
                session.SelectMasterFile();
                var info = PaceInfo.ParseCardAccess(session.ReadFile(0x011c)).Where(p => p.IsSupported)
                    .OrderByDescending(p => p.Cipher).FirstOrDefault()
                    ?? throw new UTCie.Sdk.Card.CardException("Questa carta usa una variante PACE non ancora supportata.");
                progress?.Report(CieProgress.OpeningDocument);
                session.StartSecureMessaging(Pace.AuthenticateCan(session, can.Span, info));
                session.SelectApplet();
                progress?.Report(CieProgress.ReadingDocument);
                byte[] dg1 = session.ReadFile(0x0101);
                byte[] dg2 = session.ReadFile(0x0102);
                byte[] sod = session.ReadFile(0x011d);
                VerifySignedData(sod, dg1, dg2);
                var document = ParseDocument(dg1, dg2, sod);
                if (!string.Equals(document.DocumentNumber, expectedDocumentNumber, StringComparison.Ordinal))
                    throw new UTCie.Sdk.Card.CardException("I dati ICAO non corrispondono al certificato della carta registrata.");
                return document;
            }, token).ConfigureAwait(false);
        }
        catch (CardException e) { throw new UTCie.Sdk.Card.CardException(e.SW == 0x6300 ? "CAN non corretto. Controlla le 6 cifre stampate sulla CIE." : $"Lettura ICAO interrotta: {e.Message}"); }
        catch (CryptographicException) { throw new CardProtocolException("Verifica crittografica dei dati ICAO non riuscita."); }
        catch (FormatException) { throw new CardProtocolException("Formato dei dati ICAO non valido o non supportato."); }
        // Selecting IAS changes the card application context. Check its public ID only after MRTD.
        await using (var cie = new CieCard(new BorrowedTransport(transport)))
        {
            var id = await cie.ReadServiceIdAsync(token).ConfigureAwait(false);
            var hash = Convert.ToHexString(SHA256.HashData(Convert.FromHexString(id)));
            if (hash != registered.ServiceIdHash) throw new UTCie.Sdk.Card.CardException("La carta avvicinata non è la CIE registrata.");
        }
        progress?.Report(CieProgress.Completed);
        return result;
    }

    internal static IcaoDocument ParseDocument(byte[] dg1, byte[] dg2, byte[] sod)
    {
        var root = Tlv.Parse(dg1);
        if (root.Tag != 0x61) throw new FormatException();
        byte[] mrzBytes = root.Children.Single(t => t.Tag == 0x5f1f).Value;
        if (mrzBytes.Length != 90 || mrzBytes.Any(c => c != '<' && !(c is >= (byte)'A' and <= (byte)'Z') && !(c is >= (byte)'0' and <= (byte)'9'))) throw new FormatException();
        string mrz = Encoding.ASCII.GetString(mrzBytes);
        string first = mrz[..30], second = mrz[30..60], name = mrz[60..];
        if (MrzKey.CheckDigit(first[5..14]) != first[14] || MrzKey.CheckDigit(second[..6]) != second[6] ||
            MrzKey.CheckDigit(second[8..14]) != second[14] || MrzKey.CheckDigit(first[5..] + second[..7] + second[8..15] + second[18..29]) != second[29])
            throw new FormatException("Check digit MRZ non valido.");
        string[] names = name.Split("<<", 2, StringSplitOptions.None);
        string Clean(string text) => string.Join(' ', text.Split('<', StringSplitOptions.RemoveEmptyEntries));
        var (portrait, mime) = ParsePortrait(dg2);
        return new(names.Length == 2 ? Clean(names[1]) : "", Clean(names[0]), first[5..14].TrimEnd('<'),
            second[..6], second[8..14], second[15..18], second[7].ToString(), mrz, portrait, mime, sod, DateTimeOffset.UtcNow);
    }

    internal static (byte[] Image, string Mime) ParsePortrait(byte[] dg2)
    {
        var root = Tlv.Parse(dg2);
        if (root.Tag != 0x75) throw new FormatException();
        var group = root.Children.Single(t => t.Tag == 0x7f61);
        var template = group.Children.First(t => t.Tag == 0x7f60);
        var block = template.Children.Single(t => t.Tag is 0x5f2e or 0x7f2e).Value;
        if (block.Length < 46 || !block.AsSpan(0, 8).SequenceEqual("FAC\0"u8.ToArray().Concat("010\0"u8.ToArray()).ToArray())) throw new FormatException("Formato della foto non supportato.");
        if (BinaryPrimitives.ReadUInt32BigEndian(block.AsSpan(8)) != block.Length || BinaryPrimitives.ReadUInt16BigEndian(block.AsSpan(12)) == 0) throw new FormatException();
        int recordLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(block.AsSpan(14)));
        int features = BinaryPrimitives.ReadUInt16BigEndian(block.AsSpan(18));
        int imageInfo = 14 + 20 + features * 8;
        if (recordLength < 32 || recordLength > block.Length - 14 || imageInfo + 12 >= 14 + recordLength) throw new FormatException();
        string mime = block[imageInfo + 1] switch { 0 => "image/jpeg", 1 => "image/jp2", _ => throw new FormatException("Formato foto non supportato.") };
        return (block.AsSpan(imageInfo + 12, 14 + recordLength - imageInfo - 12).ToArray(), mime);
    }

    internal static void VerifySignedData(byte[] sod, byte[] dg1, byte[] dg2)
    {
        var root = Tlv.Parse(sod);
        if (root.Tag != 0x77) throw new FormatException();
        var cms = new CmsSignedData(root.Value);
        if (cms.SignedContentType.Id != "2.23.136.1.1.1") throw new CryptographicException();
        var signer = cms.GetSignerInfos().GetSigners().Single();
        var certificate = cms.GetCertificates().EnumerateMatches(signer.SignerID).Single();
        if (!signer.Verify(certificate)) throw new CryptographicException();
        using var stream = new MemoryStream();
        cms.SignedContent.Write(stream);
        var lds = Asn1Sequence.GetInstance(stream.ToArray());
        string oid = DerObjectIdentifier.GetInstance(Asn1Sequence.GetInstance(lds[1])[0]).Id;
        if (oid is not ("1.3.14.3.2.26" or "2.16.840.1.101.3.4.2.1" or "2.16.840.1.101.3.4.2.2" or "2.16.840.1.101.3.4.2.3")) throw new CryptographicException();
        var hashes = Asn1Sequence.GetInstance(lds[2]).Select(Asn1Sequence.GetInstance)
            .ToDictionary(s => DerInteger.GetInstance(s[0]).IntValueExact, s => Asn1OctetString.GetInstance(s[1]).GetOctets());
        foreach (var (id, data) in new[] { (1, dg1), (2, dg2) })
            if (!hashes.TryGetValue(id, out var expected) || !CryptographicOperations.FixedTimeEquals(DigestUtilities.CalculateDigest(oid, data), expected)) throw new CryptographicException();
        // Integrity and embedded signer checked. This is not CSCA chain trust or chip authentication.
    }

    private sealed class BorrowedTransport(CardTransport inner) : CardTransport
    {
        public ValueTask<byte[]> TransceiveAsync(ReadOnlyMemory<byte> command, CancellationToken token = default) => inner.TransceiveAsync(command, token);
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

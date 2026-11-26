using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using UTCie.Sdk.Card;
using UTCIEID.App;

namespace UTCie.Tests;

public class CardProfileTests
{
    internal static CardProfile Sample()
    {
        using var rsa = RSA.Create(2048);
        var name = new X500DistinguishedName("C=IT, SN=ROSSI, G=ANNA, CN=RSSNNA80A01H501A/000000000001, SERIALNUMBER=IDCIT-CA12345AA");
        var request = new CertificateRequest(name, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return new(new string('1', 64), certificate.RawData, DateTimeOffset.UtcNow);
    }

    [Test] public void ReadsX500FieldsByOidAndPreservesExactCertificate()
    {
        var profile = Sample();
        var details = profile.GetCertificateDetails();
        Assert.Multiple(() =>
        {
            Assert.That(details.GivenName, Is.EqualTo("ANNA"));
            Assert.That(details.Surname, Is.EqualTo("ROSSI"));
            Assert.That(details.DocumentNumber, Is.EqualTo("CA12345AA"));
            Assert.That(details.FiscalCode, Is.EqualTo("RSSNNA80A01H501A"));
            Assert.That(details.Sha256, Is.EqualTo(Convert.ToHexString(SHA256.HashData(profile.CertificateDer))));
        });
        var roundTrip = System.Text.Json.JsonSerializer.Deserialize<CardProfile>(System.Text.Json.JsonSerializer.Serialize(profile))!;
        roundTrip.Validate();
        Assert.That(roundTrip.CertificateDer, Is.EqualTo(profile.CertificateDer));
    }

    [Test] public async Task LegacyRegistrationCanImportProfileWithoutEnteringPinAndReopenOffline()
    {
        var store = new Store();
        var first = new MainViewModel(new FakeReader(new SimulatedCie()), credentials: store);
        await first.RefreshAsync(); first.Pin = "12345678"; first.ContinueCommand.Execute(null); await Done(first);
        Assert.That(first.Error, Is.False, first.Detail);
        Assert.That(first.HasProfile, Is.True);
        Assert.That(first.SelectedTab, Is.EqualTo(2));
        Assert.That(first.ShowActions, Is.False);
        var reopened = new MainViewModel(new DisabledReader(), credentials: store);
        await reopened.RefreshAsync();
        Assert.That(reopened.HasRegistration, Is.True);
        Assert.That(reopened.HasProfile, Is.True);
        Assert.That(reopened.EnterPin, Is.False);
        Assert.That(reopened.CertificateFingerprint, Is.EqualTo(first.CertificateFingerprint));
        reopened.SelectedTab = 2;
        reopened.ForgetCardCommand.Execute(null); await Done(reopened);
        Assert.That(reopened.HasProfile, Is.False);
        Assert.That(reopened.HasRegistration, Is.False);
        Assert.That(reopened.SelectedTab, Is.Zero);
        Assert.That(store.Profile, Is.Null);
    }

    [Test] public async Task OldHashOnlyRegistrationShowsMigrationWithoutLosingPin()
    {
        var store = new Store { Card = new(new string('1', 64)) };
        var model = new MainViewModel(new DisabledReader(), credentials: store);
        await model.RefreshAsync();
        Assert.That(model.NeedsProfile, Is.True);
        Assert.That(model.HasProfile, Is.False);
        Assert.That(model.EnterPin, Is.False);
    }

    [Test] public async Task ProfileSaveFailureDoesNotClaimDataSaved()
    {
        var store = new Store { FailProfile = true };
        var model = new MainViewModel(new FakeReader(new SimulatedCie()), credentials: store);
        await model.RefreshAsync(); model.Pin = "12345678"; model.ContinueCommand.Execute(null); await Done(model);
        Assert.That(model.Error, Is.True);
        Assert.That(model.HasRegistration, Is.True);
        Assert.That(model.NeedsProfile, Is.True);
        Assert.That(model.HasProfile, Is.False);
    }

    private static async Task Done(MainViewModel model)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        while (model.Busy) await Task.Delay(5, timeout.Token);
    }
    private sealed class DisabledReader : ICardReader
    {
        public Task<ReaderStatus> GetStatusAsync(CancellationToken cancellationToken = default) => Task.FromResult(new ReaderStatus(true, false, "NFC spento"));
        public Task<ICardTransport> WaitForCardAsync(CancellationToken cancellationToken = default) => throw new AssertionException("NFC non deve essere usato.");
    }
    private sealed class Store : ICardCredentialStore, ICardProfileStore
    {
        public RegisteredCard? Card;
        public CardProfile? Profile;
        public bool FailProfile;
        public Task<RegisteredCard?> GetRegistrationAsync(CancellationToken token = default) => Task.FromResult(Card);
        public Task SaveAsync(RegisteredCard card, ReadOnlyMemory<char> pin, CancellationToken token = default) { Card = card; return Task.CompletedTask; }
        public Task<char[]> GetPinAsync(RegisteredCard card, CancellationToken token = default) => Task.FromResult("12345678".ToCharArray());
        public Task ForgetAsync(RegisteredCard card, CancellationToken token = default) { Card = null; return Task.CompletedTask; }
        public Task<CardProfile?> GetProfileAsync(RegisteredCard card, CancellationToken token = default) => Task.FromResult(Profile);
        public Task SaveProfileAsync(CardProfile profile, CancellationToken token = default)
        {
            if (FailProfile) throw new CredentialStoreException("Profile save failed");
            Profile = profile; return Task.CompletedTask;
        }
        public Task DeleteProfileAsync(RegisteredCard card, CancellationToken token = default) { Profile = null; return Task.CompletedTask; }
    }
}

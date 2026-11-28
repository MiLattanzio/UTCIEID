using System.Text.Json;
using NUnit.Framework;
using UTCie.Linux;
using UTCie.Sdk.Card;
using UTCIEID.App;

namespace UTCie.Tests;

[NonParallelizable]
public class VaultViewModelTests
{
    private string _directory = null!;
    [SetUp] public void Setup() => _directory = Path.Combine(Path.GetTempPath(), "utcieid-vault-ui-" + Guid.NewGuid().ToString("N"));
    [TearDown] public void Cleanup() { if (Directory.Exists(_directory)) Directory.Delete(_directory, true); }

    [Test] public async Task ManualPinReadsCardWithoutCreatingArchiveAndClearsOnBackground()
    {
        using var vault = new EncryptedCardVault(_directory);
        var chip = new SimulatedCie();
        var model = new MainViewModel(new FakeReader(chip), credentials: vault);
        await model.RefreshAsync();
        Assert.That(model.RememberCard, Is.False);
        Assert.That(model.EnterPin, Is.True);
        model.Pin = "12345678"; model.ContinueCommand.Execute(null); await Done(model);
        Assert.That(model.Error, Is.False, model.Detail);
        Assert.That(model.HasProfile, Is.True);
        Assert.That(model.EnterPin, Is.True);
        Assert.That(vault.Exists, Is.False);
        Assert.That(chip.PinVerifications, Is.EqualTo(1));
        model.VaultPassphrase = "some transient phrase"; model.VaultConfirmation = "some transient phrase";
        model.OnDeactivated();
        Assert.That(model.HasProfile, Is.False);
        Assert.That(model.HasRegistration, Is.False);
        Assert.That(model.Certificate, Is.Empty);
        Assert.That(model.Pin, Is.Empty);
        Assert.That(model.VaultPassphrase, Is.Empty);
        Assert.That(model.VaultConfirmation, Is.Empty);
    }

    [TestCase(false)][TestCase(true)]
    public async Task CardDataPersistenceAndPinOptInSurviveLockAndUnlock(bool savePin)
    {
        using var vault = new EncryptedCardVault(_directory);
        var model = new MainViewModel(new FreshCardReader(), credentials: vault);
        await model.RefreshAsync();
        await Create(model);
        model.RememberCard = savePin; model.Pin = "12345678"; model.ContinueCommand.Execute(null); await Done(model);
        Assert.That(model.Error, Is.False, model.Detail);
        Assert.That(model.HasProfile, Is.True);
        Assert.That(model.HasSavedPin, Is.EqualTo(savePin));
        var fingerprint = model.CertificateFingerprint;
        model.OnDeactivated();
        Assert.That(vault.IsUnlocked, Is.False);
        Assert.That(model.Status, Is.EqualTo("Archivio bloccato"));
        Assert.That(model.VaultHeader, Does.Contain("bloccato"));
        Assert.That(model.HasRegistration, Is.False);
        Assert.That(model.HasProfile, Is.False);
        Assert.That(model.EnterPin, Is.True);
        model.VaultPassphrase = VaultTests.Password; model.UnlockVaultCommand.Execute(null); await Done(model);
        Assert.That(model.Error, Is.False, model.Detail);
        Assert.That(model.CertificateFingerprint, Is.EqualTo(fingerprint));
        Assert.That(model.HasSavedPin, Is.EqualTo(savePin));
        Assert.That(model.EnterPin, Is.EqualTo(!savePin));
        if (savePin)
        {
            model.SelectedTab = 0; model.ContinueCommand.Execute(null); await Done(model);
            Assert.That(model.Error, Is.False, model.Detail);
            model.RemoveSavedPinCommand.Execute(null); await Done(model);
            Assert.That(model.HasSavedPin, Is.False);
            Assert.That(model.HasProfile, Is.True);
            Assert.That(model.EnterPin, Is.True);
        }
    }

    [Test] public async Task WrongCiePinAndWrongVaultPassphraseDoNotRetryOrPersistPin()
    {
        using var vault = new EncryptedCardVault(_directory);
        var chip = new SimulatedCie();
        var model = new MainViewModel(new FakeReader(chip), credentials: vault);
        await model.RefreshAsync(); await Create(model);
        model.RememberCard = true; model.Pin = "00000000"; model.ContinueCommand.Execute(null); await Done(model);
        Assert.That(model.Error, Is.True);
        Assert.That(model.HasSavedPin, Is.False);
        Assert.That(model.HasRegistration, Is.False);
        Assert.That(chip.PinVerifications, Is.EqualTo(1));
        Assert.That(model.Pin, Is.Empty);
        model.OnDeactivated();
        model.VaultPassphrase = "wrong password here"; model.UnlockVaultCommand.Execute(null); await Done(model);
        Assert.That(model.Error, Is.True);
        Assert.That(model.VaultUnlocked, Is.False);
        Assert.That(chip.PinVerifications, Is.EqualTo(1));
        Assert.That(model.VaultPassphrase, Is.Empty);
    }

    [Test] public async Task BackgroundDuringUnlockCancelsAndNeverRepopulatesSensitiveUi()
    {
        using var vault = new EncryptedCardVault(_directory);
        await vault.CreateAsync(VaultTests.Password.AsMemory());
        await vault.SaveCardAsync(VaultTests.Profile(), "12345678".AsMemory()); vault.Lock();
        var model = new MainViewModel(new NoCardReader(), credentials: vault);
        await model.RefreshAsync();
        model.VaultPassphrase = VaultTests.Password; model.UnlockVaultCommand.Execute(null); model.OnDeactivated();
        await Done(model);
        Assert.That(vault.IsUnlocked, Is.False);
        Assert.That(model.HasProfile, Is.False);
        Assert.That(model.HasRegistration, Is.False);
        Assert.That(model.VaultPassphrase, Is.Empty);
    }

    [Test] public async Task DeleteRequiresExplicitSecondActionAndWorksWithoutPassphrase()
    {
        using var vault = new EncryptedCardVault(_directory);
        var model = new MainViewModel(new NoCardReader(), credentials: vault);
        await Create(model); model.OnDeactivated();
        model.DeleteVaultCommand.Execute(null); await Done(model);
        Assert.That(vault.Exists, Is.True);
        model.RequestDeleteVaultCommand.Execute(null); model.CancelDeleteVaultCommand.Execute(null);
        model.DeleteVaultCommand.Execute(null); await Done(model);
        Assert.That(vault.Exists, Is.True);
        model.RequestDeleteVaultCommand.Execute(null); model.DeleteVaultCommand.Execute(null); await Done(model);
        Assert.That(vault.Exists, Is.False);
    }

    [Test] public async Task LegacyMigrationVerifiesFreshDiskDecryptBeforeRemovingPreviousCopy()
    {
        using var vault = new EncryptedCardVault(_directory);
        var legacy = new LegacyStore();
        var expected = JsonSerializer.SerializeToUtf8Bytes(legacy.Profile);
        legacy.BeforeForget = async () =>
        {
            using var independent = new EncryptedCardVault(_directory);
            await independent.UnlockAsync(VaultTests.Password.AsMemory());
            Assert.That(await independent.GetPinAsync(legacy.Card!), Is.EqualTo("12345678".ToCharArray()));
            Assert.That(JsonSerializer.SerializeToUtf8Bytes(await independent.GetProfileAsync(legacy.Card!)), Is.EqualTo(expected));
        };
        var model = new MainViewModel(new NoCardReader(), credentials: vault, legacyCredentials: legacy);
        await model.RefreshAsync(); Assert.That(model.HasLegacyCard, Is.True);
        await Create(model);
        Assert.That(model.Error, Is.False, model.Detail);
        Assert.That(legacy.Forgets, Is.EqualTo(1));
        Assert.That(legacy.Card, Is.Null);
        Assert.That(model.HasLegacyCard, Is.False);
        Assert.That(model.HasDocument, Is.True);
        Assert.That(model.HasSavedPin, Is.True);
    }

    [TestCase(false)][TestCase(true)]
    public async Task FailedOrMismatchedTransferPreservesLegacyCopy(bool differentCard)
    {
        using var vault = new EncryptedCardVault(_directory);
        var legacy = new LegacyStore();
        await vault.CreateAsync(VaultTests.Password.AsMemory());
        var profile = legacy.Profile with { ServiceIdHash = differentCard ? new string('2', 64) : legacy.Card!.ServiceIdHash };
        await vault.SaveCardAsync(profile, "87654321".AsMemory()); vault.Lock();
        var model = new MainViewModel(new NoCardReader(), credentials: vault, legacyCredentials: legacy);
        await model.RefreshAsync();
        model.VaultPassphrase = VaultTests.Password; model.UnlockVaultCommand.Execute(null); await Done(model);
        Assert.That(model.Error, Is.True);
        Assert.That(legacy.Forgets, Is.Zero);
        Assert.That(legacy.Card, Is.Not.Null);
        Assert.That(model.HasLegacyCard, Is.True);
        Assert.That(vault.IsUnlocked, Is.False);
    }

    private static async Task Create(MainViewModel model)
    {
        model.VaultPassphrase = VaultTests.Password; model.VaultConfirmation = VaultTests.Password;
        model.CreateVaultCommand.Execute(null); await Done(model);
        Assert.That(model.Error, Is.False, model.Detail);
    }
    private static async Task Done(MainViewModel model)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        while (model.Busy) await Task.Delay(5, deadline.Token);
    }
    private sealed class FreshCardReader : ICardReader
    {
        public Task<ReaderStatus> GetStatusAsync(CancellationToken cancellationToken = default) => Task.FromResult(new ReaderStatus(true, true, "NFC sintetico"));
        public Task<ICardTransport> WaitForCardAsync(CancellationToken cancellationToken = default) => Task.FromResult<ICardTransport>(new SimulatedCie());
    }
    private sealed class NoCardReader : ICardReader
    {
        public Task<ReaderStatus> GetStatusAsync(CancellationToken cancellationToken = default) => Task.FromResult(new ReaderStatus(true, true, "NFC sintetico"));
        public Task<ICardTransport> WaitForCardAsync(CancellationToken cancellationToken = default) => throw new AssertionException("Nessuna lettura NFC consentita in questa prova.");
    }
    private sealed class LegacyStore : ICardCredentialStore, ICardProfileStore
    {
        internal CardProfile Profile = VaultTests.Profile();
        internal RegisteredCard? Card = new(new string('1', 64));
        internal int Forgets;
        internal Func<Task>? BeforeForget;
        public Task<RegisteredCard?> GetRegistrationAsync(CancellationToken token = default) => Task.FromResult(Card);
        public Task<char[]> GetPinAsync(RegisteredCard card, CancellationToken token = default) => Task.FromResult("12345678".ToCharArray());
        public async Task ForgetAsync(RegisteredCard card, CancellationToken token = default) { if (BeforeForget is not null) await BeforeForget(); Forgets++; Card = null; }
        public Task<CardProfile?> GetProfileAsync(RegisteredCard card, CancellationToken token = default) => Task.FromResult<CardProfile?>(Profile);
        public Task SaveAsync(RegisteredCard card, ReadOnlyMemory<char> pin, CancellationToken token = default) => throw new AssertionException("No legacy writes");
        public Task SaveProfileAsync(CardProfile profile, CancellationToken token = default) => throw new AssertionException("No legacy writes");
        public Task DeleteProfileAsync(RegisteredCard card, CancellationToken token = default) => throw new AssertionException("Use atomic legacy Forget");
    }
}

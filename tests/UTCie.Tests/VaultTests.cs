using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;
using UTCie.Linux;
using UTCie.Sdk.Card;

namespace UTCie.Tests;

[NonParallelizable]
public class VaultTests
{
    internal const string Password = "UTCIEID test passphrase";
    private string _directory = null!;
    private string Packet => Path.Combine(_directory, "vault-v1.bin");
    [SetUp] public void Setup() => _directory = Path.Combine(Path.GetTempPath(), "utcieid-vault-tests-" + Guid.NewGuid().ToString("N"));
    [TearDown] public void Cleanup() { if (Directory.Exists(_directory)) Directory.Delete(_directory, true); }
    internal static CardProfile Profile()
    {
        return CardProfileTests.Sample() with { Document = new("SYNTHETIC", "EXAMPLE", "CA12345AA", "800101", "300101", "ITA", "F",
            new string('<', 90), [1, 2, 3, 4, 5], "image/jpeg", [6, 7, 8], DateTimeOffset.UtcNow) };
    }

    [Test] public void Argon2idAgreesWithIndependentReferenceLibrary()
    {
        // libargon2 argon2id_hash_raw: v19, t=3, m=65536 KiB, p=1, 32 bytes; salt 00..0F.
        var key = EncryptedCardVault.DeriveKey(Encoding.UTF8.GetBytes(Password), Enumerable.Range(0, 16).Select(i => (byte)i).ToArray());
        Assert.That(Convert.ToHexString(key), Is.EqualTo("F74F2ABD7152E08653E8575457A1269219EDB0D4237EB6EDB5E59F7564BA07FF"));
    }

    [Test] public void StandardBuildContainsNoSecretServiceBackend() =>
        Assert.That(typeof(EncryptedCardVault).Assembly.GetType("UTCie.Linux.SecretServicePinStore"), Is.Null);

    [Test] public async Task SeparateInstanceRestoresExactPinCertificateAndPhotoButNothingWhileLocked()
    {
        var profile = Profile(); var card = new RegisteredCard(profile.ServiceIdHash);
        using (var first = new EncryptedCardVault(_directory))
        {
            await first.CreateAsync(Password.AsMemory());
            await first.SaveCardAsync(profile, "12345678".AsMemory());
            var isolated = (await first.GetProfileAsync(card))!;
            Array.Clear(isolated.CertificateDer); Array.Clear(isolated.Document!.Portrait);
            Assert.That((await first.GetProfileAsync(card))!.CertificateDer, Is.EqualTo(profile.CertificateDer));
            first.Lock();
            Assert.That(first.HasSavedPin, Is.False);
            Assert.That(await first.GetRegistrationAsync(), Is.Null);
            Assert.That(await first.GetProfileAsync(card), Is.Null);
            await Fails<CredentialStoreException>(async () => await first.GetPinAsync(card));
        }
        using var second = new EncryptedCardVault(_directory);
        await second.UnlockAsync(Password.AsMemory());
        Assert.That(await second.GetPinAsync(card), Is.EqualTo("12345678".ToCharArray()));
        var restored = (await second.GetProfileAsync(card))!;
        Assert.That(restored.CertificateDer, Is.EqualTo(profile.CertificateDer));
        Assert.That(restored.Document!.Portrait, Is.EqualTo(profile.Document!.Portrait));
        Assert.That(restored.Document.Sod, Is.EqualTo(profile.Document.Sod));
        Assert.That(restored.SavedAt, Is.EqualTo(profile.SavedAt));
        Assert.That(restored.Document.ReadAt, Is.EqualTo(profile.Document.ReadAt));
        await Fails<CredentialStoreException>(async () => await second.GetPinAsync(new(new string('2', 64))));
    }

    [Test] public async Task WrongPasswordAndEveryAuthenticatedRegionRejectTamperingWithoutChangingFile()
    {
        using var vault = new EncryptedCardVault(_directory);
        await vault.CreateAsync(Password.AsMemory());
        await vault.SaveCardAsync(Profile(), "12345678".AsMemory()); vault.Lock();
        byte[] good = File.ReadAllBytes(Packet);
        await Fails<CredentialStoreException>(async () => await vault.UnlockAsync("a wrong passphrase".AsMemory()));
        Assert.That(File.ReadAllBytes(Packet), Is.EqualTo(good));
        foreach (int offset in new[] { 0, 8, 24, 36, 40, good.Length - 1 })
        {
            byte[] bad = good.ToArray(); bad[offset] ^= 1; File.WriteAllBytes(Packet, bad);
            await Fails<CredentialStoreException>(async () => await vault.UnlockAsync(Password.AsMemory()));
            Assert.That(vault.IsUnlocked, Is.False);
            Assert.That(File.ReadAllBytes(Packet), Is.EqualTo(bad));
        }
        File.WriteAllBytes(Packet, good);
        await vault.UnlockAsync(Password.AsMemory());
        Assert.That(vault.HasSavedPin, Is.True);
    }

    [Test] public async Task RejectsTruncationOversizeAndUnknownFormatWithoutDerivation()
    {
        using var vault = new EncryptedCardVault(_directory);
        await vault.CreateAsync(Password.AsMemory()); vault.Lock();
        byte[] good = File.ReadAllBytes(Packet);
        foreach (byte[] invalid in new[] { Array.Empty<byte>(), good[..^1], new byte[EncryptedCardVault.MaxPlaintext + 57], "UTCIEV02"u8.ToArray().Concat(good.Skip(8)).ToArray() })
        {
            File.WriteAllBytes(Packet, invalid);
            await Fails<CredentialStoreException>(async () => await vault.UnlockAsync(Password.AsMemory()));
            Assert.That(vault.IsUnlocked, Is.False);
        }
    }

    [Test] public async Task OnlyCiphertextReachesPrivateFilesAndNoncesChangeOnEveryWrite()
    {
        using var vault = new EncryptedCardVault(_directory);
        await vault.CreateAsync(Password.AsMemory());
        byte[] before = File.ReadAllBytes(Packet);
        var profile = Profile(); await vault.SaveCardAsync(profile, "12345678".AsMemory());
        byte[] after = File.ReadAllBytes(Packet);
        Assert.That(after.AsSpan(24, 12).ToArray(), Is.Not.EqualTo(before.AsSpan(24, 12).ToArray()));
        foreach (string path in Directory.GetFiles(_directory))
        {
            byte[] content = File.ReadAllBytes(path);
            foreach (string secret in new[] { Password, "12345678", "SYNTHETIC", profile.ServiceIdHash, Convert.ToBase64String(profile.CertificateDer) })
                Assert.That(content.AsSpan().IndexOf(Encoding.UTF8.GetBytes(secret)), Is.EqualTo(-1));
            Assert.That(content.AsSpan().IndexOf(profile.CertificateDer), Is.EqualTo(-1));
            if (OperatingSystem.IsLinux()) Assert.That(File.GetUnixFileMode(path), Is.EqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite));
        }
        Assert.That(Directory.GetFiles(_directory, "*.tmp"), Is.Empty);
        if (OperatingSystem.IsLinux()) Assert.That(File.GetUnixFileMode(_directory), Is.EqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute));
        using var another = new EncryptedCardVault(Path.Combine(_directory, "another"));
        await another.CreateAsync(Password.AsMemory());
        var packet = File.ReadAllBytes(Path.Combine(_directory, "another", "vault-v1.bin"));
        Assert.That(packet.AsSpan(8, 16).ToArray(), Is.Not.EqualTo(after.AsSpan(8, 16).ToArray()));
    }

    [Test] public async Task DataOnlyAndPinRemovalPreserveProfileAcrossRestart()
    {
        var profile = Profile(); var card = new RegisteredCard(profile.ServiceIdHash);
        using var vault = new EncryptedCardVault(_directory);
        await vault.CreateAsync(Password.AsMemory());
        await vault.SaveCardAsync(profile, ReadOnlyMemory<char>.Empty);
        Assert.That(vault.HasSavedPin, Is.False);
        await vault.SaveAsync(card, "12345678".AsMemory());
        Assert.That(vault.HasSavedPin, Is.True);
        await vault.RemovePinAsync(); vault.Lock(); await vault.UnlockAsync(Password.AsMemory());
        Assert.That(vault.HasSavedPin, Is.False);
        Assert.That((await vault.GetProfileAsync(card))!.CertificateDer, Is.EqualTo(profile.CertificateDer));
        await vault.ForgetAsync(card); vault.Lock(); await vault.UnlockAsync(Password.AsMemory());
        Assert.That(await vault.GetRegistrationAsync(), Is.Null);
        Assert.That(await vault.GetProfileAsync(card), Is.Null);
        vault.Lock(); await vault.DeleteAsync(); Assert.That(vault.Exists, Is.False);
    }

    [Test] public async Task StaleWriterCannotOverwriteAnotherSessionsChangesOrRecreateDeletedArchive()
    {
        using var first = new EncryptedCardVault(_directory);
        using var second = new EncryptedCardVault(_directory);
        await first.CreateAsync(Password.AsMemory()); await second.UnlockAsync(Password.AsMemory());
        var profile = Profile(); await first.SaveCardAsync(profile, "12345678".AsMemory());
        byte[] current = File.ReadAllBytes(Packet);
        await Fails<CredentialStoreException>(async () => await second.SaveCardAsync(profile, "87654321".AsMemory()));
        Assert.That(File.ReadAllBytes(Packet), Is.EqualTo(current));
        await first.DeleteAsync();
        await Fails<CredentialStoreException>(async () => await second.SaveCardAsync(profile, "87654321".AsMemory()));
        Assert.That(second.Exists, Is.False);
    }

    [Test] public async Task LockAndCancellationDuringKdfCannotLeaveArchiveUnlocked()
    {
        using var vault = new EncryptedCardVault(_directory);
        await vault.CreateAsync(Password.AsMemory()); vault.Lock();
        Task opening = vault.UnlockAsync(Password.AsMemory()); vault.Lock();
        await Fails<OperationCanceledException>(async () => await opening);
        Assert.That(vault.IsUnlocked, Is.False);
        using var cancelled = new CancellationTokenSource();
        opening = vault.UnlockAsync(Password.AsMemory(), cancelled.Token); cancelled.Cancel();
        await Fails<OperationCanceledException>(async () => await opening);
        Assert.That(vault.IsUnlocked, Is.False);
    }

    private static async Task Fails<T>(Func<Task> operation) where T : Exception
    {
        try { await operation(); }
        catch (Exception e) { Assert.That(e, Is.InstanceOf<T>()); return; }
        Assert.Fail($"Expected {typeof(T).Name}.");
    }

    [TestCase("12345678")][TestCase("           short ")][TestCase("")]
    public void RejectsWeakPassphraseBeforeCreatingFiles(string password)
    {
        using var vault = new EncryptedCardVault(_directory);
        Assert.Throws<CredentialStoreException>(() => vault.CreateAsync(password.AsMemory()));
        Assert.That(Directory.Exists(_directory), Is.False);
    }
}

namespace UTCie.Sdk.Card;

/// <summary>Optional encrypted persistence. A locked vault never exposes a registration or PIN.</summary>
public interface ILocalVault : ICardCredentialStore, ICardProfileStore
{
    bool Exists { get; }
    bool IsUnlocked { get; }
    bool HasSavedPin { get; }
    Task CreateAsync(ReadOnlyMemory<char> passphrase, CancellationToken token = default);
    Task UnlockAsync(ReadOnlyMemory<char> passphrase, CancellationToken token = default);
    void Lock();
    Task SaveCardAsync(CardProfile profile, ReadOnlyMemory<char> pin, CancellationToken token = default);
    Task RemovePinAsync(CancellationToken token = default);
    Task DeleteAsync(CancellationToken token = default);
}

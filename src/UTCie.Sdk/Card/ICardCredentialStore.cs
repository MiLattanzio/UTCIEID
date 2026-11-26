namespace UTCie.Sdk.Card;

public sealed record RegisteredCard(string ServiceIdHash);

public interface ICardCredentialStore
{
    Task<RegisteredCard?> GetRegistrationAsync(CancellationToken token = default);
    Task SaveAsync(RegisteredCard card, ReadOnlyMemory<char> pin, CancellationToken token = default);
    Task<char[]> GetPinAsync(RegisteredCard card, CancellationToken token = default);
    Task ForgetAsync(RegisteredCard card, CancellationToken token = default);
}

public sealed class CredentialStoreException(string message) : Exception(message);

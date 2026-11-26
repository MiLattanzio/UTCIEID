namespace UTCie.Sdk.Card;

/// <summary>A single, exclusively acquired ISO-DEP card. Dispose releases the card.</summary>
public interface ICardTransport : IAsyncDisposable
{
    ValueTask<byte[]> TransceiveAsync(ReadOnlyMemory<byte> command, CancellationToken cancellationToken);
}

public interface ICardReader
{
    Task<ReaderStatus> GetStatusAsync(CancellationToken cancellationToken = default);
    Task<ICardTransport> WaitForCardAsync(CancellationToken cancellationToken = default);
}

public sealed record ReaderStatus(bool Available, bool Enabled, string Description);

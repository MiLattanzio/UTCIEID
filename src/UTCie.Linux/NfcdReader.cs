using Tmds.DBus.Protocol;
using UTCie.Sdk.Card;

namespace UTCie.Linux;

/// <summary>nfcd ISO-DEP adapter. Uses the org.neard alias covered by Ubuntu Touch's nfc AppArmor policy.</summary>
public sealed class NfcdReader : ICardReader
{
    private readonly string _address;
    private readonly string _service;
    public NfcdReader() : this(DBusAddress.System ?? "unix:path=/var/run/dbus/system_bus_socket", "org.neard") { }
    internal NfcdReader(string address, string service) { _address = address; _service = service; }

    public async Task<ReaderStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var bus = new NfcConnection(_address, _service);
            await bus.ConnectAsync(cancellationToken).ConfigureAwait(false);
            var adapters = await bus.PathsAsync("/", "Daemon", "GetAdapters", cancellationToken).ConfigureAwait(false);
            if (adapters.Length == 0) return new(false, false, "Nessun adattatore NFC disponibile.");
            foreach (var adapter in adapters)
                if (await bus.BoolAsync(adapter, "Adapter", "GetEnabled", cancellationToken).ConfigureAwait(false) &&
                    await bus.BoolAsync(adapter, "Adapter", "GetPowered", cancellationToken).ConfigureAwait(false))
                    return new(true, true, "NFC pronto. Puoi avvicinare la tua CIE.");
            return new(true, false, "Attiva NFC nelle impostazioni di Ubuntu Touch.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception e) when (e is DBusExceptionBase or IOException or TimeoutException)
        {
            return new(false, false, "Servizio NFC non accessibile. Verifica nfcd e il permesso NFC dell'app.");
        }
    }

    public async Task<ICardTransport> WaitForCardAsync(CancellationToken cancellationToken = default)
    {
        var bus = new NfcConnection(_address, _service);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(60));
        var token = deadline.Token;
        try
        {
            await bus.ConnectAsync(token).ConfigureAwait(false);
            var adapters = await bus.PathsAsync("/", "Daemon", "GetAdapters", token).ConfigureAwait(false);
            if (adapters.Length == 0) throw new CardException("Nessun lettore NFC disponibile.");
            // Like Android FLAG_READER_SKIP_NDEF_CHECK, leave ISO-DEP application selection to us.
            foreach (var adapter in adapters)
                await bus.SkipNdefAsync(adapter, token).ConfigureAwait(false);
            // Request is scoped to this D-Bus connection; close releases it, including on cancellation.
            await bus.RequestReaderModeAsync(token).ConfigureAwait(false);
            while (true)
            {
                token.ThrowIfCancellationRequested();
                foreach (var adapter in adapters)
                {
                    if (!await bus.BoolAsync(adapter, "Adapter", "GetEnabled", token).ConfigureAwait(false) ||
                        !await bus.BoolAsync(adapter, "Adapter", "GetPowered", token).ConfigureAwait(false))
                        continue;
                    var tags = await bus.PathsAsync(adapter, "Adapter", "GetTags", token).ConfigureAwait(false);
                    foreach (var tag in tags)
                    {
                        var interfaces = await bus.StringsAsync(tag, "Tag", "GetInterfaces", token).ConfigureAwait(false);
                        if (!interfaces.Contains("org.sailfishos.nfc.IsoDep")) continue;
                        await bus.AcquireAsync(tag, token).ConfigureAwait(false);
                        return new NfcdTransport(bus, tag);
                    }
                }
                // Only while a user-initiated operation is waiting; no background polling.
                await Task.Delay(250, token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { bus.Dispose(); throw new TimeoutException("Nessuna carta rilevata entro 60 secondi."); }
        catch { bus.Dispose(); throw; }
    }

    private sealed class NfcdTransport(NfcConnection bus, string path) : ICardTransport
    {
        private int _inFlight;
        private bool _disposed;
        public async ValueTask<byte[]> TransceiveAsync(ReadOnlyMemory<byte> command, CancellationToken token)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (Interlocked.CompareExchange(ref _inFlight, 1, 0) != 0) throw new InvalidOperationException("APDU già in corso.");
            try { return await bus.TransmitAsync(path, ApduCommand.Parse(command.Span), token).ConfigureAwait(false); }
            catch { _disposed = true; bus.Dispose(); throw; }
            finally { Volatile.Write(ref _inFlight, 0); }
        }
        public ValueTask DisposeAsync()
        {
            _disposed = true;
            // nfcd releases both the tag lock and the mode request when its client disconnects.
            bus.Dispose();
            return ValueTask.CompletedTask;
        }
    }
}

internal sealed class NfcConnection(string address, string service) : IDisposable
{
    private readonly DBusConnection _connection = new(address);
    public Task ConnectAsync(CancellationToken token) => BoundedAsync(_connection.ConnectAsync().AsTask(), token);

    private MessageBuffer EmptyCall(string path, string iface, string member)
    {
        using var writer = _connection.GetMessageWriter();
        writer.WriteMethodCallHeader(destination: service, path: path, @interface: "org.sailfishos.nfc." + iface, member: member);
        return writer.CreateMessage();
    }

    public Task<string[]> PathsAsync(string path, string iface, string member, CancellationToken token) =>
        BoundedAsync(_connection.CallMethodAsync(EmptyCall(path, iface, member), static (reply, _) =>
            reply.GetBodyReader().ReadArrayOfObjectPath().Select(p => p.ToString()).ToArray()), token);
    public Task<string[]> StringsAsync(string path, string iface, string member, CancellationToken token) =>
        BoundedAsync(_connection.CallMethodAsync(EmptyCall(path, iface, member), static (reply, _) => reply.GetBodyReader().ReadArrayOfString()), token);
    public Task<bool> BoolAsync(string path, string iface, string member, CancellationToken token) =>
        BoundedAsync(_connection.CallMethodAsync(EmptyCall(path, iface, member), static (reply, _) => reply.GetBodyReader().ReadBool()), token);

    public Task<uint> RequestReaderModeAsync(CancellationToken token)
    {
        using var writer = _connection.GetMessageWriter();
        writer.WriteMethodCallHeader(destination: service, path: "/", @interface: "org.sailfishos.nfc.Daemon", member: "RequestMode", signature: "uu");
        writer.WriteUInt32(2); writer.WriteUInt32(0);
        return BoundedAsync(_connection.CallMethodAsync(writer.CreateMessage(), static (reply, _) => reply.GetBodyReader().ReadUInt32()), token);
    }

    public Task AcquireAsync(string path, CancellationToken token)
    {
        using var writer = _connection.GetMessageWriter();
        writer.WriteMethodCallHeader(destination: service, path: path, @interface: "org.sailfishos.nfc.Tag", member: "Acquire", signature: "b");
        writer.WriteBool(true);
        return BoundedAsync(_connection.CallMethodAsync(writer.CreateMessage()), token);
    }

    public Task<uint> SkipNdefAsync(string path, CancellationToken token)
    {
        using var writer = _connection.GetMessageWriter();
        writer.WriteMethodCallHeader(destination: service, path: path, @interface: "org.sailfishos.nfc.Adapter", member: "RequestParams", signature: "a{sv}b");
        var dictionary = writer.WriteDictionaryStart();
        writer.WriteDictionaryEntryStart(); writer.WriteString("T4_NDEF"); writer.WriteVariantBool(false);
        writer.WriteDictionaryEnd(dictionary); writer.WriteBool(false);
        // nfcd restores parameters automatically when this private connection closes.
        return BoundedAsync(_connection.CallMethodAsync(writer.CreateMessage(), static (reply, _) => reply.GetBodyReader().ReadUInt32()), token);
    }

    public Task<byte[]> TransmitAsync(string path, ApduCommand command, CancellationToken token)
    {
        using var writer = _connection.GetMessageWriter();
        writer.WriteMethodCallHeader(destination: service, path: path, @interface: "org.sailfishos.nfc.IsoDep", member: "Transmit", signature: "yyyyayu");
        writer.WriteByte(command.Cla); writer.WriteByte(command.Ins); writer.WriteByte(command.P1); writer.WriteByte(command.P2);
        writer.WriteArray(command.Data);
        writer.WriteUInt32((uint)(command.Le ?? 0));
        return BoundedAsync(_connection.CallMethodAsync(writer.CreateMessage(), static (reply, _) =>
        {
            var reader = reply.GetBodyReader();
            byte[] data = reader.ReadArrayOfByte();
            return (byte[])[..data, reader.ReadByte(), reader.ReadByte()];
        }), token);
    }

    private async Task<T> BoundedAsync<T>(Task<T> operation, CancellationToken token)
    {
        try { return await operation.WaitAsync(TimeSpan.FromSeconds(10), token).ConfigureAwait(false); }
        catch
        {
            Dispose();
            _ = operation.ContinueWith(t => { _ = t.Exception; }, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            throw;
        }
    }
    private async Task BoundedAsync(Task operation, CancellationToken token)
    {
        try { await operation.WaitAsync(TimeSpan.FromSeconds(10), token).ConfigureAwait(false); }
        catch
        {
            Dispose();
            _ = operation.ContinueWith(t => { _ = t.Exception; }, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            throw;
        }
    }
    public void Dispose() => _connection.Dispose();
}

using System.Runtime.InteropServices;
using System.Text.Json;
using UTCie.Sdk.Card;

namespace UTCie.Linux;

/// <summary>Full PIN in the persistent login keyring via libsecret; only the card hash is kept in the app's metadata.</summary>
public sealed partial class SecretServicePinStore : ICardCredentialStore, ICardProfileStore
{
    private readonly string _metadata;
    private readonly SemaphoreSlim _gate = new(1, 1);
    public SecretServicePinStore(string? dataDirectory = null)
    {
        string root = Environment.GetEnvironmentVariable("XDG_DATA_HOME") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local/share");
        _metadata = Path.Combine(dataDirectory ?? Path.Combine(root, "utcieid.milattanzio"), "registered-card.json");
    }

    public async Task<RegisteredCard?> GetRegistrationAsync(CancellationToken token = default)
    {
        if (!File.Exists(_metadata)) return null;
        if (new FileInfo(_metadata).Length > 512) throw Failure();
        var card = JsonSerializer.Deserialize<RegisteredCard>(await File.ReadAllTextAsync(_metadata, token).ConfigureAwait(false));
        if (card is null) throw Failure();
        Validate(card);
        return card;
    }

    public async Task SaveAsync(RegisteredCard card, ReadOnlyMemory<char> pin, CancellationToken token = default)
    {
        Validate(card);
        if (!CiePin.IsValid(pin.Span)) throw new ArgumentException("PIN non valido.", nameof(pin));
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var previous = await GetRegistrationAsync(token).ConfigureAwait(false);
            await ExecuteAsync(card, (attributes, cancellation) =>
            {
                IntPtr password = Marshal.AllocHGlobal(9);
                try
                {
                    for (int i = 0; i < 8; i++) Marshal.WriteByte(password, i, (byte)pin.Span[i]);
                    Marshal.WriteByte(password, 8, 0);
                    // Explicit persistent login collection: never silently store only in a session keyring.
                    int stored = Native.secret_password_storev_sync(IntPtr.Zero, attributes,
                        "/org/freedesktop/secrets/collection/login", "UTCIEID · PIN della CIE", password, cancellation, out var error);
                    CheckError(error);
                    if (stored == 0) throw Failure();
                    return true;
                }
                finally { for (int i = 0; i < 9; i++) Marshal.WriteByte(password, i, 0); Marshal.FreeHGlobal(password); }
            }, token).ConfigureAwait(false);
            var directory = Path.GetDirectoryName(_metadata)!;
            Directory.CreateDirectory(directory);
            if (OperatingSystem.IsLinux()) File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            string temp = _metadata + ".tmp";
            try
            {
                await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(card), token).ConfigureAwait(false);
                if (OperatingSystem.IsLinux()) File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                File.Move(temp, _metadata, true);
            }
            finally { if (File.Exists(temp)) File.Delete(temp); }
            if (previous is not null && previous != card)
            {
                await DeleteProfileAsync(previous, token).ConfigureAwait(false);
                await DeleteSecretAsync(previous, token).ConfigureAwait(false);
            }
        }
        finally { _gate.Release(); }
    }

    public Task<char[]> GetPinAsync(RegisteredCard card, CancellationToken token = default)
    {
        Validate(card);
        return ExecuteAsync(card, (attributes, cancellation) =>
        {
            IntPtr password = Native.secret_password_lookupv_sync(IntPtr.Zero, attributes, cancellation, out var error);
            try
            {
                CheckError(error);
                if (password == IntPtr.Zero) throw Failure();
                char[] pin = new char[8];
                for (int i = 0; i < 8; i++)
                {
                    byte c = Marshal.ReadByte(password, i);
                    if (c is < (byte)'0' or > (byte)'9') { Array.Clear(pin); throw Failure(); }
                    pin[i] = (char)c;
                }
                if (Marshal.ReadByte(password, 8) != 0) { Array.Clear(pin); throw Failure(); }
                return pin;
            }
            finally { if (password != IntPtr.Zero) Native.secret_password_free(password); }
        }, token);
    }

    public async Task ForgetAsync(RegisteredCard card, CancellationToken token = default)
    {
        Validate(card);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            await DeleteProfileAsync(card, token).ConfigureAwait(false);
            await DeleteSecretAsync(card, token).ConfigureAwait(false);
            if (await GetRegistrationAsync(token).ConfigureAwait(false) == card) File.Delete(_metadata);
        }
        finally { _gate.Release(); }
    }

    private Task<bool> DeleteSecretAsync(RegisteredCard card, CancellationToken token) => ExecuteAsync(card, (attributes, cancellation) =>
    {
        Native.secret_password_clearv_sync(IntPtr.Zero, attributes, cancellation, out var error);
        CheckError(error);
        // clear only removes unlocked items. A remaining locked secret is a failure, not a successful forget.
        var check = Native.secret_password_lookupv_sync(IntPtr.Zero, attributes, cancellation, out error);
        try { CheckError(error); if (check != IntPtr.Zero) throw Failure(); }
        finally { if (check != IntPtr.Zero) Native.secret_password_free(check); }
        return true;
    }, token);

    private static async Task<T> ExecuteAsync<T>(RegisteredCard card, Func<IntPtr, IntPtr, T> action, CancellationToken token, string application = "utcieid.milattanzio")
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));
        try
        {
            return await Task.Run(() =>
            {
                timeout.Token.ThrowIfCancellationRequested();
                IntPtr table = Native.g_hash_table_new_full(Native.StringHash, Native.StringEqual, Native.Free, Native.Free);
                IntPtr cancellation = Native.g_cancellable_new();
                using var registration = timeout.Token.Register(() => Native.g_cancellable_cancel(cancellation));
                try
                {
                    Native.g_hash_table_insert(table, Native.g_strdup("application"), Native.g_strdup(application));
                    Native.g_hash_table_insert(table, Native.g_strdup("card-sha256"), Native.g_strdup(card.ServiceIdHash));
                    return action(table, cancellation);
                }
                finally
                {
                    registration.Dispose();
                    Native.g_object_unref(cancellation);
                    Native.g_hash_table_destroy(table);
                }
            }, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception) when (token.IsCancellationRequested) { throw new OperationCanceledException(token); }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or TypeInitializationException || timeout.IsCancellationRequested)
        { throw Failure(); }
    }

    private static void Validate(RegisteredCard card)
    {
        if (card.ServiceIdHash.Length != 64 || card.ServiceIdHash.Any(c => !Uri.IsHexDigit(c))) throw Failure();
    }
    private static CredentialStoreException Failure() => new("Portachiavi non disponibile o bloccato. Il PIN non è stato salvato in un file. Sblocca il portachiavi o usa il PIN manualmente.");
    private static void CheckError(IntPtr error) { if (error != IntPtr.Zero) { Native.g_error_free(error); throw Failure(); } }

    private static class Native
    {
        private const string Secret = "libsecret-1.so.0", Glib = "libglib-2.0.so.0", Gio = "libgio-2.0.so.0", GObject = "libgobject-2.0.so.0";
        private static readonly IntPtr Library = NativeLibrary.Load(Glib);
        internal static readonly IntPtr StringHash = NativeLibrary.GetExport(Library, "g_str_hash");
        internal static readonly IntPtr StringEqual = NativeLibrary.GetExport(Library, "g_str_equal");
        internal static readonly IntPtr Free = NativeLibrary.GetExport(Library, "g_free");
        [DllImport(Secret, CallingConvention = CallingConvention.Cdecl)] internal static extern int secret_password_storev_sync(IntPtr schema, IntPtr attributes, [MarshalAs(UnmanagedType.LPUTF8Str)] string collection, [MarshalAs(UnmanagedType.LPUTF8Str)] string label, IntPtr password, IntPtr cancellable, out IntPtr error);
        [DllImport(Secret, CallingConvention = CallingConvention.Cdecl)] internal static extern IntPtr secret_password_lookupv_sync(IntPtr schema, IntPtr attributes, IntPtr cancellable, out IntPtr error);
        [DllImport(Secret, CallingConvention = CallingConvention.Cdecl)] internal static extern int secret_password_clearv_sync(IntPtr schema, IntPtr attributes, IntPtr cancellable, out IntPtr error);
        [DllImport(Secret, CallingConvention = CallingConvention.Cdecl)] internal static extern void secret_password_free(IntPtr password);
        [DllImport(Glib, CallingConvention = CallingConvention.Cdecl)] internal static extern IntPtr g_hash_table_new_full(IntPtr hash, IntPtr equal, IntPtr keyDestroy, IntPtr valueDestroy);
        [DllImport(Glib, CallingConvention = CallingConvention.Cdecl)] internal static extern void g_hash_table_insert(IntPtr table, IntPtr key, IntPtr value);
        [DllImport(Glib, CallingConvention = CallingConvention.Cdecl)] internal static extern void g_hash_table_destroy(IntPtr table);
        [DllImport(Glib, CallingConvention = CallingConvention.Cdecl)] internal static extern IntPtr g_strdup([MarshalAs(UnmanagedType.LPUTF8Str)] string text);
        [DllImport(Glib, CallingConvention = CallingConvention.Cdecl)] internal static extern void g_error_free(IntPtr error);
        [DllImport(Gio, CallingConvention = CallingConvention.Cdecl)] internal static extern IntPtr g_cancellable_new();
        [DllImport(Gio, CallingConvention = CallingConvention.Cdecl)] internal static extern void g_cancellable_cancel(IntPtr cancellable);
        [DllImport(GObject, CallingConvention = CallingConvention.Cdecl)] internal static extern void g_object_unref(IntPtr instance);
    }
}

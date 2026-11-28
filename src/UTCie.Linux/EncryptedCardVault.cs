using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using UTCie.Sdk.Card;

namespace UTCie.Linux;

/// <summary>Versioned Argon2id/AES-256-GCM vault, wholly inside the application's data directory.</summary>
public sealed class EncryptedCardVault : ILocalVault, IDisposable
{
    internal const int HeaderLength = 40, TagLength = 16, MaxPlaintext = 2 * 1024 * 1024;
    internal static ReadOnlySpan<byte> Magic => "UTCIEV01"u8;
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly JsonSerializerOptions Json = new() { MaxDepth = 24, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    private readonly string _directory, _path;
    private readonly object _sync = new();
    private readonly SemaphoreSlim _gate = new(1, 1);
    private byte[]? _key, _salt, _fingerprint;
    private Contents? _contents;
    private long _epoch;
    private bool _disposed;

    public EncryptedCardVault(string? directory = null)
    {
        string root = Environment.GetEnvironmentVariable("XDG_DATA_HOME") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local/share");
        _directory = directory ?? Path.Combine(root, "utcieid.milattanzio");
        _path = Path.Combine(_directory, "vault-v1.bin");
    }
    public bool Exists => File.Exists(_path);
    public bool IsUnlocked { get { lock (_sync) return _key is not null; } }
    public bool HasSavedPin { get { lock (_sync) return _key is not null && _contents?.Pin is { Length: 8 }; } }

    public static void ValidateNewPassphrase(ReadOnlySpan<char> value)
    {
        if (value.Length is < 12 or > 1024 || value.Trim().Length < 12)
            throw new CredentialStoreException("Usa una passphrase di almeno 12 caratteri, preferibilmente più parole. Non usare il PIN della CIE.");
    }

    public Task CreateAsync(ReadOnlyMemory<char> passphrase, CancellationToken token = default)
    {
        ValidateNewPassphrase(passphrase.Span);
        return OpenAsync(passphrase, create: true, token);
    }
    public Task UnlockAsync(ReadOnlyMemory<char> passphrase, CancellationToken token = default) => OpenAsync(passphrase, create: false, token);

    private async Task OpenAsync(ReadOnlyMemory<char> passphrase, bool create, CancellationToken token)
    {
        if (passphrase.Length is < 1 or > 1024) throw InvalidPassword();
        byte[] password;
        try { password = new byte[Utf8.GetByteCount(passphrase.Span)]; Utf8.GetBytes(passphrase.Span, password); }
        catch (EncoderFallbackException) { throw InvalidPassword(); }
        try
        {
            await _gate.WaitAsync(token).ConfigureAwait(false);
            try
            {
                long epoch;
                lock (_sync) { ObjectDisposedException.ThrowIf(_disposed, this); LockCore(); epoch = _epoch; }
                await Task.Run(() =>
                {
                    byte[]? key = null, plain = null;
                    Contents? data = null;
                    try
                    {
                        token.ThrowIfCancellationRequested();
                        byte[]? packet = create ? null : ReadPacket();
                        if (create && Exists) throw new CredentialStoreException("L'archivio esiste già. Sbloccalo con la sua passphrase.");
                        byte[] salt = packet is null ? RandomNumberGenerator.GetBytes(16) : packet.AsSpan(8, 16).ToArray();
                        key = DeriveKey(password, salt);
                        token.ThrowIfCancellationRequested();
                        if (packet is null) data = new();
                        else
                        {
                            int size = packet.Length - HeaderLength - TagLength;
                            plain = new byte[size];
                            using var aes = new AesGcm(key, TagLength);
                            aes.Decrypt(packet.AsSpan(24, 12), packet.AsSpan(HeaderLength, size), packet.AsSpan(HeaderLength + size, TagLength), plain, packet.AsSpan(0, HeaderLength));
                            data = JsonSerializer.Deserialize<Contents>(plain, Json) ?? throw InvalidPassword();
                            Validate(data);
                        }
                        lock (_sync)
                        {
                            CheckEpoch(epoch, token);
                            using var diskLock = AcquireDiskLock();
                            if (create) packet = WritePacket(data, key, salt, replace: false, token);
                            else if (!ReadPacket().AsSpan().SequenceEqual(packet)) throw Changed();
                            _key = key; key = null;
                            _salt = salt;
                            _fingerprint = SHA256.HashData(packet!);
                            _contents = data; data = null;
                        }
                    }
                    catch (Exception e) when (e is CryptographicException or JsonException or CardException or ArgumentException)
                    { throw InvalidPassword(); }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                    { throw new CredentialStoreException("Archivio non disponibile. Verifica lo spazio libero e riprova."); }
                    finally { Clear(key); Clear(plain); Wipe(data); }
                }, token).ConfigureAwait(false);
            }
            finally { _gate.Release(); }
        }
        finally { Clear(password); }
    }

    public void Lock() { lock (_sync) LockCore(); }
    private void LockCore()
    {
        _epoch++;
        Clear(_key); _key = null; _salt = null; _fingerprint = null;
        Wipe(_contents); _contents = null;
    }

    public Task<RegisteredCard?> GetRegistrationAsync(CancellationToken token = default)
    { token.ThrowIfCancellationRequested(); lock (_sync) return Task.FromResult(_contents?.Card); }
    public Task<char[]> GetPinAsync(RegisteredCard card, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        lock (_sync)
        {
            RequireUnlocked();
            if (_contents!.Card != card || _contents.Pin is not { Length: 8 }) throw new CredentialStoreException("Non è presente un PIN salvato per questa carta. Inseriscilo manualmente.");
            return Task.FromResult(_contents.Pin.ToArray());
        }
    }
    public Task<CardProfile?> GetProfileAsync(RegisteredCard card, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        lock (_sync) return Task.FromResult(_contents?.Card == card ? CloneProfile(_contents.Profile) : null);
    }
    public Task SaveCardAsync(CardProfile profile, ReadOnlyMemory<char> pin, CancellationToken token = default)
    {
        profile.Validate();
        if (!pin.IsEmpty && !CiePin.IsValid(pin.Span)) throw new ArgumentException("PIN non valido.", nameof(pin));
        return ChangeAsync(data => { Wipe(data); data.Card = new(profile.ServiceIdHash); data.Pin = pin.IsEmpty ? null : pin.ToArray(); data.Profile = CloneProfile(profile); }, token);
    }
    public Task SaveAsync(RegisteredCard card, ReadOnlyMemory<char> pin, CancellationToken token = default)
    {
        if (!CiePin.IsValid(pin.Span)) throw new ArgumentException("PIN non valido.", nameof(pin));
        return ChangeAsync(data =>
        {
            if (data.Card != card) { Wipe(data); data.Profile = null; }
            if (data.Pin is not null) Array.Clear(data.Pin);
            data.Card = card; data.Pin = pin.ToArray();
        }, token);
    }
    public Task SaveProfileAsync(CardProfile profile, CancellationToken token = default)
    {
        profile.Validate();
        return ChangeAsync(data =>
        {
            if (data.Card?.ServiceIdHash != profile.ServiceIdHash) throw new CredentialStoreException("Il documento appartiene a un'altra carta.");
            WipeProfile(data.Profile); data.Profile = CloneProfile(profile);
        }, token);
    }
    public Task RemovePinAsync(CancellationToken token = default) => ChangeAsync(data => { if (data.Pin is not null) Array.Clear(data.Pin); data.Pin = null; }, token);
    public Task DeleteProfileAsync(RegisteredCard card, CancellationToken token = default) => ChangeAsync(data =>
    { if (data.Card == card) { WipeProfile(data.Profile); data.Profile = null; } }, token);
    public Task ForgetAsync(RegisteredCard card, CancellationToken token = default) => ChangeAsync(data =>
    { if (data.Card == card) { Wipe(data); data.Card = null; data.Pin = null; data.Profile = null; } }, token);

    private async Task ChangeAsync(Action<Contents> change, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            // Run disk encryption off the UI thread. Lock() cannot leave an operation with a stale key.
            long epoch;
            lock (_sync) { RequireUnlocked(); epoch = _epoch; }
            await Task.Run(() =>
            {
                lock (_sync)
                {
                    CheckEpoch(epoch, token); RequireUnlocked();
                    using var diskLock = AcquireDiskLock();
                    if (!SHA256.HashData(ReadPacket()).AsSpan().SequenceEqual(_fingerprint)) throw Changed();
                    var next = Clone(_contents!);
                    try
                    {
                        change(next); Validate(next);
                        var packet = WritePacket(next, _key!, _salt!, replace: true, token);
                        Wipe(_contents); _contents = next; next = null;
                        _fingerprint = SHA256.HashData(packet);
                    }
                    finally { Wipe(next); }
                }
            }, token).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        { throw new CredentialStoreException("Salvataggio non riuscito. I dati precedenti non sono stati sostituiti."); }
        finally { _gate.Release(); }
    }

    /// <summary>Caller must obtain explicit confirmation; also works for a forgotten passphrase.</summary>
    public async Task DeleteAsync(CancellationToken token = default)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            lock (_sync)
            {
                token.ThrowIfCancellationRequested();
                using var diskLock = AcquireDiskLock();
                File.Delete(_path); LockCore();
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        { throw new CredentialStoreException("Non è stato possibile eliminare l'archivio."); }
        finally { _gate.Release(); }
    }

    private byte[] ReadPacket()
    {
        using var file = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is < HeaderLength + TagLength + 2 or > HeaderLength + TagLength + MaxPlaintext) throw InvalidPassword();
        byte[] bytes = new byte[(int)file.Length]; file.ReadExactly(bytes);
        if (file.ReadByte() != -1 || !bytes.AsSpan(0, 8).SequenceEqual(Magic)
            || BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(36, 4)) != bytes.Length - HeaderLength - TagLength) throw InvalidPassword();
        return bytes;
    }
    private byte[] WritePacket(Contents data, byte[] key, byte[] salt, bool replace, CancellationToken token)
    {
        byte[] plain = JsonSerializer.SerializeToUtf8Bytes(data, Json);
        string? temporary = null;
        try
        {
            if (plain.Length > MaxPlaintext) throw new CredentialStoreException("I dati superano la dimensione massima dell'archivio.");
            byte[] packet = new byte[HeaderLength + plain.Length + TagLength];
            Magic.CopyTo(packet); salt.CopyTo(packet, 8); RandomNumberGenerator.Fill(packet.AsSpan(24, 12));
            BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(36, 4), plain.Length);
            using (var aes = new AesGcm(key, TagLength))
                aes.Encrypt(packet.AsSpan(24, 12), plain, packet.AsSpan(HeaderLength, plain.Length), packet.AsSpan(HeaderLength + plain.Length, TagLength), packet.AsSpan(0, HeaderLength));
            temporary = Path.Combine(_directory, ".vault-" + Guid.NewGuid().ToString("N") + ".tmp");
            using (var stream = OpenPrivateFile(temporary, FileMode.CreateNew, FileAccess.Write))
            { stream.Write(packet); stream.Flush(flushToDisk: true); }
            token.ThrowIfCancellationRequested();
            File.Move(temporary, _path, replace); temporary = null;
            return packet;
        }
        finally { Clear(plain); if (temporary is not null) File.Delete(temporary); }
    }
    private FileStream AcquireDiskLock()
    {
        if (OperatingSystem.IsLinux()) Directory.CreateDirectory(_directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        else Directory.CreateDirectory(_directory);
        return OpenPrivateFile(Path.Combine(_directory, ".vault.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite);
    }
    private static FileStream OpenPrivateFile(string path, FileMode mode, FileAccess access)
    {
        var options = new FileStreamOptions { Mode = mode, Access = access, Share = FileShare.None };
        if (OperatingSystem.IsLinux()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        return new FileStream(path, options);
    }
    internal static byte[] DeriveKey(byte[] password, byte[] salt)
    {
        // Format v1 fixes the cost: hostile files cannot choose expensive KDF parameters.
        var parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id).WithVersion(Argon2Parameters.Version13)
            .WithMemoryAsKB(65536).WithIterations(3).WithParallelism(1).WithSalt(salt).Build();
        var generator = new Argon2BytesGenerator(); generator.Init(parameters);
        byte[] key = new byte[32];
        try { generator.GenerateBytes(password, key); return key; }
        catch { Clear(key); throw; }
    }
    private void RequireUnlocked()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_key is null || _contents is null) throw new CredentialStoreException("Sblocca l'archivio oppure usa il PIN manualmente.");
    }
    private void CheckEpoch(long epoch, CancellationToken token)
    { token.ThrowIfCancellationRequested(); if (_disposed || epoch != _epoch) throw new OperationCanceledException("Archivio bloccato durante l'operazione."); }
    private static CredentialStoreException InvalidPassword() => new("Passphrase non corretta o archivio danneggiato. Nessun dato è stato modificato.");
    private static CredentialStoreException Changed() => new("L'archivio è stato modificato da un'altra sessione. Bloccalo e riaprilo.");
    private static void Validate(Contents data)
    {
        if (data.Card is null) { if (data.Pin is not null || data.Profile is not null) throw InvalidPassword(); return; }
        if (data.Card.ServiceIdHash is not { Length: 64 } || data.Card.ServiceIdHash.Any(c => !Uri.IsHexDigit(c))) throw InvalidPassword();
        if (data.Pin is not null && !CiePin.IsValid(data.Pin)) throw InvalidPassword();
        if (data.Profile is not null)
        { data.Profile.Validate(); if (data.Profile.ServiceIdHash != data.Card.ServiceIdHash) throw InvalidPassword(); }
    }
    private static Contents Clone(Contents data) => new() { Card = data.Card, Pin = data.Pin?.ToArray(), Profile = CloneProfile(data.Profile) };
    private static CardProfile? CloneProfile(CardProfile? profile) => profile is null ? null : profile with
    { CertificateDer = profile.CertificateDer.ToArray(), Document = profile.Document is null ? null : profile.Document with { Portrait = profile.Document.Portrait.ToArray(), Sod = profile.Document.Sod.ToArray() } };
    private static void Wipe(Contents? data) { if (data?.Pin is not null) Array.Clear(data.Pin); WipeProfile(data?.Profile); }
    private static void WipeProfile(CardProfile? profile) { Clear(profile?.CertificateDer); Clear(profile?.Document?.Portrait); Clear(profile?.Document?.Sod); }
    private static void Clear(byte[]? data) { if (data is not null) CryptographicOperations.ZeroMemory(data); }
    public void Dispose() { lock (_sync) { LockCore(); _disposed = true; } }
    private sealed class Contents
    {
        public RegisteredCard? Card { get; set; }
        public char[]? Pin { get; set; }
        public CardProfile? Profile { get; set; }
    }
}

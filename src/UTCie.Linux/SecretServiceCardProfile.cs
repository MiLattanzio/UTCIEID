using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using UTCie.Sdk.Card;

namespace UTCie.Linux;

public sealed partial class SecretServicePinStore
{
    // A distinct application attribute is essential: legacy PIN lookups use only application + card-sha256.
    private const string ProfileApplication = "utcieid.milattanzio.card-profile";
    private const int ProfileLimit = 2 * 1024 * 1024;

    public Task<CardProfile?> GetProfileAsync(RegisteredCard card, CancellationToken token = default)
    {
        Validate(card);
        return ExecuteAsync(card, (attributes, cancellation) =>
        {
            IntPtr secret = Native.secret_password_lookupv_sync(IntPtr.Zero, attributes, cancellation, out var error);
            try
            {
                CheckError(error);
                if (secret == IntPtr.Zero) return null;
                int length = 0;
                while (length < ProfileLimit && Marshal.ReadByte(secret, length) != 0) length++;
                if (length == ProfileLimit) throw new CredentialStoreException("Profilo salvato troppo grande.");
                byte[] json = new byte[length];
                try
                {
                    Marshal.Copy(secret, json, 0, length);
                    var profile = JsonSerializer.Deserialize<CardProfile>(json) ?? throw Failure();
                    profile.Validate();
                    if (profile.ServiceIdHash != card.ServiceIdHash) throw Failure();
                    return profile;
                }
                finally { CryptographicOperations.ZeroMemory(json); }
            }
            finally { if (secret != IntPtr.Zero) Native.secret_password_free(secret); }
        }, token, ProfileApplication);
    }

    public async Task SaveProfileAsync(CardProfile profile, CancellationToken token = default)
    {
        profile.Validate();
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(profile);
        try
        {
            if (json.Length >= ProfileLimit) throw new CredentialStoreException("Profilo della carta troppo grande.");
            await ExecuteAsync(new(profile.ServiceIdHash), (attributes, cancellation) =>
            {
                IntPtr secret = Marshal.AllocHGlobal(json.Length + 1);
                try
                {
                    Marshal.Copy(json, 0, secret, json.Length);
                    Marshal.WriteByte(secret, json.Length, 0);
                    int saved = Native.secret_password_storev_sync(IntPtr.Zero, attributes,
                        "/org/freedesktop/secrets/collection/login", "UTCIEID · Dati e certificato della CIE", secret, cancellation, out var error);
                    CheckError(error);
                    if (saved == 0) throw Failure();
                    return true;
                }
                finally
                {
                    for (int i = 0; i <= json.Length; i++) Marshal.WriteByte(secret, i, 0);
                    Marshal.FreeHGlobal(secret);
                }
            }, token, ProfileApplication).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(json); }
    }

    public Task DeleteProfileAsync(RegisteredCard card, CancellationToken token = default)
    {
        Validate(card);
        return ExecuteAsync(card, (attributes, cancellation) =>
        {
            Native.secret_password_clearv_sync(IntPtr.Zero, attributes, cancellation, out var error);
            CheckError(error);
            var remaining = Native.secret_password_lookupv_sync(IntPtr.Zero, attributes, cancellation, out error);
            try { CheckError(error); if (remaining != IntPtr.Zero) throw Failure(); }
            finally { if (remaining != IntPtr.Zero) Native.secret_password_free(remaining); }
            return true;
        }, token, ProfileApplication);
    }
}

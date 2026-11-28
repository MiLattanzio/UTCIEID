using System.Security.Cryptography;
using System.Text.Json;
using System.Windows.Input;
using UTCie.Sdk.Card;

namespace UTCIEID.App;

public sealed partial class MainViewModel
{
    private readonly ILocalVault? _vault;
    private readonly ICardCredentialStore? _legacyCredentials;
    private bool _profileSaved, _saveCardData = true, _vaultPanelOpen, _confirmDeleteVault, _hasLegacyCard;
    private string _vaultPassphrase = "", _vaultConfirmation = "";
    public bool VaultAvailable => _vault is not null;
    public bool VaultExists => _vault?.Exists == true;
    public bool VaultUnlocked => _vault?.IsUnlocked == true;
    public bool VaultNeedsUnlock => VaultExists && !VaultUnlocked;
    public bool VaultNeedsCreation => VaultAvailable && !VaultExists;
    public string VaultHeader => VaultUnlocked ? "Archivio · sbloccato" : VaultExists ? "Archivio · bloccato" : "Archivio della carta";
    public bool HasSavedPin => _vault?.HasSavedPin ?? (_credentials is not null && HasRegistration);
    public bool CanOpenVault => !Busy && !VaultUnlocked && VaultPassphrase.Length > 0;
    public bool VaultPanelOpen { get => _vaultPanelOpen; set => Set(ref _vaultPanelOpen, value); }
    public bool ConfirmDeleteVault { get => _confirmDeleteVault; private set => Set(ref _confirmDeleteVault, value); }
    public bool HasLegacyCard { get => _hasLegacyCard; private set { Set(ref _hasLegacyCard, value); Notify(nameof(CreateVaultLabel)); } }
    public string CreateVaultLabel => HasLegacyCard ? "Crea archivio e trasferisci la carta" : "Crea archivio cifrato";
    public string VaultPassphrase { get => _vaultPassphrase; set { Set(ref _vaultPassphrase, value); Notify(nameof(CanOpenVault)); } }
    public string VaultConfirmation { get => _vaultConfirmation; set => Set(ref _vaultConfirmation, value); }
    public bool SaveCardData { get => _saveCardData; set { Set(ref _saveCardData, value); if (!value) RememberCard = false; Notify(nameof(CanRegister)); } }
    public string ProfileStorageNotice => _profileSaved
        ? "Foto, dati e certificato sono nell'archivio cifrato. Sbloccalo dopo la riapertura per consultarli."
        : "Questi dati restano solo nella sessione corrente e vengono nascosti quando lasci l'app.";
    public string VaultSummary => VaultUnlocked ? "Archivio sbloccato · si blocca quando lasci l'app"
        : VaultExists ? "Archivio bloccato · puoi anche usare il PIN manuale"
        : "Facoltativo · usa il PIN manuale oppure conserva la carta in un archivio cifrato";
    public ICommand CreateVaultCommand { get; private set; } = null!;
    public ICommand UnlockVaultCommand { get; private set; } = null!;
    public ICommand LockVaultCommand { get; private set; } = null!;
    public ICommand RemoveSavedPinCommand { get; private set; } = null!;
    public ICommand RequestDeleteVaultCommand { get; private set; } = null!;
    public ICommand CancelDeleteVaultCommand { get; private set; } = null!;
    public ICommand DeleteVaultCommand { get; private set; } = null!;

    private void InitializeVaultCommands()
    {
        CreateVaultCommand = new AsyncCommand(() => OpenVaultAsync(create: true));
        UnlockVaultCommand = new AsyncCommand(() => OpenVaultAsync(create: false));
        LockVaultCommand = new ActionCommand(LockVault);
        RemoveSavedPinCommand = new AsyncCommand(RemoveSavedPinAsync);
        RequestDeleteVaultCommand = new ActionCommand(() => { if (!Busy) ConfirmDeleteVault = true; });
        CancelDeleteVaultCommand = new ActionCommand(() => ConfirmDeleteVault = false);
        DeleteVaultCommand = new AsyncCommand(DeleteVaultAsync);
    }

    private async Task LoadRegistrationAsync(CancellationToken token)
    {
        if (_credentials is null) return;
        var card = await _credentials.GetRegistrationAsync(token);
        var profile = card is not null && _profiles is not null ? await _profiles.GetProfileAsync(card, token) : null;
        token.ThrowIfCancellationRequested();
        _registered = card;
        _profileSaved = profile is not null;
        SetProfile(profile); RegistrationChanged();
    }

    private async Task OpenVaultAsync(bool create)
    {
        if (_vault is null || Busy) return;
        if (create && VaultPassphrase != VaultConfirmation)
        { Error = true; Status = "Le passphrase non coincidono"; Detail = "Ripetila identica nei due campi."; return; }
        char[] password = VaultPassphrase.ToCharArray();
        VaultPassphrase = ""; VaultConfirmation = "";
        Busy = true; Error = false; ResetNfcGuide();
        using var operation = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        _operation = operation;
        try
        {
            Status = create ? "Creazione dell'archivio…" : "Sblocco dell'archivio…";
            Detail = "La passphrase non viene salvata.";
            if (create) await _vault.CreateAsync(password, operation.Token);
            else await _vault.UnlockAsync(password, operation.Token);
            if (_legacyCredentials is not null && HasLegacyCard) await TransferLegacyAsync(password, operation.Token);
            operation.Token.ThrowIfCancellationRequested();
            await LoadRegistrationAsync(operation.Token);
            UseSavedPin = HasSavedPin; RememberCard = HasSavedPin;
            VaultPanelOpen = false;
            Status = "Archivio sbloccato";
            Detail = HasRegistration ? "La carta salvata è disponibile nel tab Dati." : "Puoi leggere la CIE e scegliere se salvare anche il PIN.";
        }
        catch (OperationCanceledException) { _vault.Lock(); ClearCardSession(); Status = "Archivio bloccato"; Detail = "Lo sblocco è stato annullato."; }
        catch (Exception e)
        {
            _vault.Lock(); ClearCardSession(); Error = true; Status = "Archivio non aperto";
            Detail = e is CredentialStoreException ? e.Message : "Non è stato possibile aprire l'archivio. Puoi usare il PIN manuale.";
        }
        finally { Array.Clear(password); _operation = null; Busy = false; NotifyVault(); }
    }

    // Only the separate development migration build supplies legacyCredentials.
    // Verify a fresh decrypt from disk before removing the old app-owned keyring entries.
    private async Task TransferLegacyAsync(char[] password, CancellationToken token)
    {
        var previous = await _legacyCredentials!.GetRegistrationAsync(token);
        if (previous is null) { HasLegacyCard = false; return; }
        if (_legacyCredentials is not ICardProfileStore previousProfiles) throw new CredentialStoreException("Impossibile trasferire il profilo precedente.");
        char[] pin = await _legacyCredentials.GetPinAsync(previous, token);
        CardProfile? profile = null;
        try
        {
            profile = await previousProfiles.GetProfileAsync(previous, token);
            var existing = await _vault!.GetRegistrationAsync(token);
            if (existing is null)
            {
                Status = "Trasferimento della carta…";
                if (profile is not null) await _vault.SaveCardAsync(profile, pin, token);
                else await _vault.SaveAsync(previous, pin, token);
            }
            else if (existing != previous) throw new CredentialStoreException("L'archivio contiene un'altra carta. I dati precedenti non sono stati rimossi.");
            token.ThrowIfCancellationRequested();
            _vault.Lock();
            await _vault.UnlockAsync(password, token);
            var loadedPin = await _vault.GetPinAsync(previous, token);
            try { if (!loadedPin.AsSpan().SequenceEqual(pin)) throw new CredentialStoreException("Verifica del trasferimento non riuscita. La copia precedente è conservata."); }
            finally { Array.Clear(loadedPin); }
            var loadedProfile = await _vault.GetProfileAsync(previous, token);
            byte[] expected = JsonSerializer.SerializeToUtf8Bytes(profile), actual = JsonSerializer.SerializeToUtf8Bytes(loadedProfile);
            try { if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(expected), SHA256.HashData(actual))) throw new CredentialStoreException("Il profilo trasferito non coincide. La copia precedente è conservata."); }
            finally { CryptographicOperations.ZeroMemory(expected); CryptographicOperations.ZeroMemory(actual); }
            token.ThrowIfCancellationRequested();
            await _legacyCredentials.ForgetAsync(previous, token);
            HasLegacyCard = false;
        }
        finally { Array.Clear(pin); }
    }

    private void LockVault()
    {
        Cancel(); _vault?.Lock();
        VaultPassphrase = ""; VaultConfirmation = ""; ConfirmDeleteVault = false;
        if (_vault is not null) ClearCardSession();
        if (VaultExists && !Busy)
        {
            Status = "Archivio bloccato";
            Detail = "Sbloccalo con la passphrase per ritrovare la carta e usare il PIN salvato. Puoi anche inserire il PIN manualmente.";
            Error = false;
        }
        NotifyVault();
    }
    private void ClearCardSession()
    {
        _registered = null; _profileSaved = false;
        Pin = ""; Can = ""; Certificate = ""; SetProfile(null); ClearCompletion();
        if (SelectedTab == 2) SelectedTab = 0;
        RegistrationChanged();
    }
    private async Task RemoveSavedPinAsync()
    {
        if (_vault is null || !VaultUnlocked || Busy) return;
        Busy = true;
        using var operation = new CancellationTokenSource(TimeSpan.FromSeconds(30)); _operation = operation;
        try
        {
            await _vault.RemovePinAsync(operation.Token); operation.Token.ThrowIfCancellationRequested();
            UseSavedPin = false; RememberCard = false; Status = "PIN salvato rimosso"; Detail = "Foto, dati e certificato restano nell'archivio."; Error = false;
        }
        catch (OperationCanceledException) { Status = "Operazione annullata"; }
        catch (Exception e) { Error = true; Status = "PIN non rimosso"; Detail = e is CredentialStoreException ? e.Message : "Riprova dopo aver sbloccato l'archivio."; }
        finally { _operation = null; Busy = false; NotifyVault(); }
    }
    private async Task DeleteVaultAsync()
    {
        if (_vault is null || Busy || !ConfirmDeleteVault) return;
        Busy = true;
        try { await _vault.DeleteAsync(); ClearCardSession(); Status = "Archivio eliminato"; Detail = "Puoi creare un nuovo archivio e rileggere la CIE."; Error = false; }
        catch (Exception e) { Error = true; Status = "Archivio non eliminato"; Detail = e is CredentialStoreException ? e.Message : "Non è stato possibile eliminare l'archivio."; }
        finally { ConfirmDeleteVault = false; Busy = false; NotifyVault(); }
    }
    private void NotifyVault()
    {
        foreach (string name in new[] { nameof(VaultExists), nameof(VaultUnlocked), nameof(VaultNeedsUnlock), nameof(VaultNeedsCreation), nameof(VaultSummary), nameof(VaultHeader),
            nameof(HasSavedPin), nameof(CanOpenVault), nameof(EnterPin), nameof(CanContinue), nameof(CanRegister), nameof(ProfileStorageNotice) }) Notify(name);
    }
}

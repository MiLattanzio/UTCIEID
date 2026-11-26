using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using UTCie.Sdk;
using UTCie.Sdk.Authentication;
using UTCie.Sdk.Card;
using IcaoDocumentReader = UTCie.Sdk.Icao.IcaoDocumentReader;

namespace UTCIEID.App;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly ICardReader _reader;
    private readonly ICardCredentialStore? _credentials;
    private RegisteredCard? _registered;
    private readonly ICardProfileStore? _profiles;
    private readonly ICieQrIdentityProvider _qrProvider;
    private CardProfile? _profile;
    private CertificateDetails? _identity;
    private string _can = "";
    private bool _useSavedPin = true, _rememberCard = true;
    private CancellationTokenSource? _operation;
    private int _selectedTab, _environmentIndex;
    private string _pin = "", _requestLink = "", _status = "Controllo del lettore NFC…", _detail = "", _certificate = "";
    private bool _busy, _nfcReady, _error;
    private Uri? _completion;
    private string _otp = "";
    private string _nfcGuideTitle = "", _nfcGuideDetail = "", _nfcGuideColor = "#E4EEF8";
    private bool _cardDetected;
    public event PropertyChangedEventHandler? PropertyChanged;
    public event Action? CardDetected;
    public Func<Uri, Task<bool>>? OpenUriAsync { get; set; }
    public Func<CancellationToken, Task<string?>>? ReadCameraQrAsync { get; set; }
    private bool _scanningQr;
    public bool ScanningQr { get => _scanningQr; private set => Set(ref _scanningQr, value); }
    public string[] Environments { get; } = ["Produzione", "Preproduzione", "Collaudo"];

    public MainViewModel(ICardReader reader, string? startupLink = null, ICardCredentialStore? credentials = null, ICardProfileStore? profiles = null,
        ICieQrIdentityProvider? qrProvider = null)
    {
        _reader = reader;
        _credentials = credentials;
        _profiles = profiles ?? credentials as ICardProfileStore;
        _qrProvider = qrProvider ?? new CieQrIdentityProvider();
        ContinueCommand = new AsyncCommand(ContinueAsync);
        RefreshCommand = new AsyncCommand(RefreshAsync);
        CancelCommand = new ActionCommand(Cancel);
        OpenBrowserCommand = new AsyncCommand(OpenBrowserAsync);
        ForgetCardCommand = new AsyncCommand(ForgetCardAsync);
        LocateCardCommand = new AsyncCommand(LocateCardAsync);
        ImportDocumentCommand = new AsyncCommand(ImportDocumentAsync);
        ScanQrCommand = new AsyncCommand(ScanQrAsync);
        if (startupLink is not null) ApplyLink(startupLink);
    }

    public int SelectedTab { get => _selectedTab; set { if (Set(ref _selectedTab, value)) { ClearCompletion(); Notify(nameof(ActionLabel)); Notify(nameof(ShowActions)); Notify(nameof(CanRegister)); } } }
    public int EnvironmentIndex { get => _environmentIndex; set { if (Set(ref _environmentIndex, value)) { ClearCompletion(); Notify(nameof(RequestService)); } } }
    public string Pin { get => _pin; set { Set(ref _pin, value); Notify(nameof(CanContinue)); } }
    public string RequestLink { get => _requestLink; set { if (Set(ref _requestLink, value)) { ClearCompletion(); Notify(nameof(ActionLabel)); Notify(nameof(RequestService)); } } }
    public string Status { get => _status; private set => Set(ref _status, value); }
    public string Detail { get => _detail; private set => Set(ref _detail, value); }
    public string Certificate { get => _certificate; private set { Set(ref _certificate, value); Notify(nameof(HasCertificate)); } }
    public string NfcGuideTitle { get => _nfcGuideTitle; private set { Set(ref _nfcGuideTitle, value); Notify(nameof(HasNfcGuide)); } }
    public string NfcGuideDetail { get => _nfcGuideDetail; private set => Set(ref _nfcGuideDetail, value); }
    public string NfcGuideColor { get => _nfcGuideColor; private set => Set(ref _nfcGuideColor, value); }
    public bool HasNfcGuide => NfcGuideTitle.Length != 0;
    public bool Busy { get => _busy; private set { Set(ref _busy, value); Notify(nameof(NotBusy)); Notify(nameof(CanContinue)); Notify(nameof(CanImportDocument)); } }
    public bool NotBusy => !Busy;
    public bool Error { get => _error; private set => Set(ref _error, value); }
    public bool HasCertificate => Certificate.Length != 0;
    public bool HasCompletion => _completion is not null;
    public string Otp { get => _otp; private set { Set(ref _otp, value); Notify(nameof(HasOtp)); } }
    public bool HasOtp => Otp.Length != 0;
    private bool IsQrRequest => Uri.TryCreate(RequestLink, UriKind.Absolute, out var uri) && uri.AbsolutePath == "/idp/erroreQr.jsp";
    public string RequestService
    {
        get
        {
            try { return IsQrRequest ? "Accesso a " + CieQrAuthenticationRequest.Parse(RequestLink, (CieEnvironment)EnvironmentIndex).ServiceName : ""; }
            catch (ArgumentException) { return ""; }
        }
    }
    public bool HasRegistration => _registered is not null;
    public bool UseSavedPin { get => _useSavedPin; set { Set(ref _useSavedPin, value); Pin = ""; Notify(nameof(EnterPin)); Notify(nameof(CanContinue)); Notify(nameof(CanRegister)); } }
    public bool RememberCard { get => _rememberCard; set => Set(ref _rememberCard, value); }
    public bool EnterPin => !HasRegistration || !UseSavedPin;
    public bool CanRegister => EnterPin && SelectedTab == 0;
    public bool ShowActions => SelectedTab < 2;
    public bool CanContinue => !Busy && _nfcReady && (!EnterPin || CiePin.IsValid(Pin));
    public string ActionLabel => SelectedTab == 1 ? IsQrRequest ? "Genera codice OTP" : "Accedi con la CIE" : "Leggi la tua CIE";
    public string Can { get => _can; set { Set(ref _can, value); Notify(nameof(CanImportDocument)); } }
    public bool HasProfile => _profile is not null;
    public bool NeedsProfile => HasRegistration && !HasProfile;
    public bool HasDocument => _profile?.Document is not null;
    public bool NeedsDocument => HasProfile && !HasDocument;
    public IcaoDocument? Document => _profile?.Document;
    public string GivenName => Display(_identity?.GivenName);
    public string Surname => Display(_identity?.Surname);
    public string DocumentNumber => Display(_identity?.DocumentNumber);
    public string FiscalCode => Display(_identity?.FiscalCode);
    public string CertificateSubject => Display(_identity?.Subject);
    public string CertificateIssuer => Display(_identity?.Issuer);
    public string CertificateValidity => _identity is null ? "" : $"Dal {_identity.NotBefore:dd/MM/yyyy} al {_identity.NotAfter:dd/MM/yyyy}";
    public string CertificateSerial => Display(_identity?.SerialNumber);
    public string CertificateFingerprint => Display(_identity?.Sha256);
    public string DocumentBirth => MrzDate(Document?.DateOfBirth);
    public string DocumentExpiry => MrzDate(Document?.DateOfExpiry);
    public string Nationality => Display(Document?.Nationality ?? _identity?.Country);
    public string Sex => Display(Document?.Sex);
    public bool CanImportDocument => !Busy && _nfcReady && HasProfile && _profiles is not null && Can.Length == 6 && Can.All(char.IsAsciiDigit);
    public ICommand ImportDocumentCommand { get; }
    public ICommand ScanQrCommand { get; }
    public ICommand ContinueCommand { get; }
    public ICommand RefreshCommand { get; }
    public ICommand CancelCommand { get; }
    public ICommand OpenBrowserCommand { get; }
    public ICommand ForgetCardCommand { get; }
    public ICommand LocateCardCommand { get; }

    public async Task RefreshAsync()
    {
        if (Busy) return;
        Busy = true; Error = false;
        using var operation = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        _operation = operation;
        try
        {
            if (_credentials is not null)
            {
                _registered = await _credentials.GetRegistrationAsync(operation.Token);
                RegistrationChanged();
                if (_registered is not null && _profiles is not null)
                    SetProfile(await _profiles.GetProfileAsync(_registered, operation.Token));
            }
            var status = await _reader.GetStatusAsync(operation.Token);
            _nfcReady = status.Enabled;
            Status = status.Description;
            Detail = status.Enabled ? "La carta va mantenuta ferma sul retro del telefono." : "Tocca «Ricontrolla NFC» dopo aver attivato il lettore.";
            Error = !status.Enabled;
            if (status.Enabled && SelectedTab == 1 && RequestLink.Length != 0)
            {
                try { ParseRequest(); }
                catch (ArgumentException e) { ShowRequestError(e); }
            }
        }
        catch (CredentialStoreException e) { Error = true; Status = "Dati della carta non disponibili"; Detail = e.Message; }
        catch (OperationCanceledException) { Status = "Controllo NFC annullato."; }
        catch { Error = true; Status = "Lettore NFC non disponibile."; }
        finally { _operation = null; Busy = false; }
    }

    private async Task ContinueAsync()
    {
        if (!CanContinue) return;
        CieAuthenticationRequest? request = null;
        CieQrAuthenticationRequest? qrRequest = null;
        try
        {
            if (SelectedTab == 1)
            {
                (request, qrRequest) = ParseRequest();
                if (qrRequest is not null && !EnterPin && _identity is not null && _identity.DocumentNumber != qrRequest.DocumentNumber)
                    throw new ArgumentException("Il QR è destinato a una carta diversa da quella registrata. Controlla il numero inserito nel sito.");
            }
        }
        catch (ArgumentException e) { ShowRequestError(e); return; }
        bool fromKeyring = !EnterPin;
        var registered = _registered;
        char[] pin = fromKeyring ? [] : Pin.ToCharArray();
        Pin = ""; Certificate = ""; ClearCompletion(); Error = false; Busy = true; ResetNfcGuide();
        using var operation = new CancellationTokenSource(TimeSpan.FromSeconds(120));
        _operation = operation;
        var progress = new Progress<CieProgress>(p => { if (_operation == operation && !operation.IsCancellationRequested) OnProgress(p); });
        try
        {
            if (fromKeyring)
            {
                Status = "Apertura del portachiavi…";
                pin = await _credentials!.GetPinAsync(registered!, operation.Token);
            }
            var client = new CieClient(_reader);
            if (qrRequest is not null)
            {
                string otp = await client.AuthenticateQrAsync(qrRequest, pin, _qrProvider, progress, operation.Token,
                    fromKeyring ? registered!.ServiceIdHash : null);
                operation.Token.ThrowIfCancellationRequested();
                Otp = otp;
                Status = "Codice OTP pronto";
                Detail = "Riporta le quattro cifre nella pagina del computer e premi «Procedi». Puoi allontanare la carta.";
            }
            else if (request is null)
            {
                var cert = await client.ReadCertificateAsync(pin, progress, operation.Token, fromKeyring ? registered!.ServiceIdHash : null);
                operation.Token.ThrowIfCancellationRequested();
                Certificate = $"{cert.Subject}\nCertificato valido fino al {cert.NotAfter:dd/MM/yyyy}";
                Status = "CIE letta correttamente";
                Detail = "Puoi allontanare la carta. I dati restano solo in questa sessione.";
                if (!fromKeyring && RememberCard && _credentials is not null)
                {
                    Status = "Registrazione nel portachiavi…";
                    var registration = new RegisteredCard(cert.ServiceIdHash);
                    await _credentials.SaveAsync(registration, pin, operation.Token);
                    _registered = registration;
                    UseSavedPin = true;
                    RegistrationChanged();
                    Status = "CIE registrata";
                    Detail = "Il PIN completo è nel portachiavi. Dal prossimo accesso basta avvicinare questa carta.";
                }
                if (_registered?.ServiceIdHash == cert.ServiceIdHash && _profiles is not null)
                {
                    var document = _profile?.ServiceIdHash == cert.ServiceIdHash ? _profile.Document : null;
                    var profile = new CardProfile(cert.ServiceIdHash, cert.CertificateDer, DateTimeOffset.UtcNow, document);
                    await _profiles.SaveProfileAsync(profile, operation.Token);
                    SetProfile(profile);
                    SelectedTab = 2;
                    Detail = "Dati e certificato salvati nel portachiavi del dispositivo. Per aggiungere la foto usa il CAN stampato sulla CIE.";
                }
            }
            else
            {
                using var provider = new CieIdentityProvider(request.Environment);
                _completion = await client.AuthenticateAsync(request, pin, provider, progress, operation.Token, fromKeyring ? registered!.ServiceIdHash : null);
                operation.Token.ThrowIfCancellationRequested();
                Notify(nameof(HasCompletion));
                Status = "Firma della richiesta completata";
                Detail = "Puoi allontanare la carta. Continua nel browser per completare l'accesso.";
            }
        }
        catch (OperationCanceledException) { ClearCompletion(); Status = "Operazione annullata"; Detail = "Quando vuoi riprovare, avvia una nuova lettura."; }
        catch (PinException e) { if (fromKeyring) UseSavedPin = false; Error = true; Status = e.Message; Detail = "Controlla il PIN prima di un nuovo tentativo. Nessun tentativo automatico."; }
        catch (CredentialStoreException e) { RetainPinForRetry(); Error = true; Status = "Portachiavi non disponibile"; Detail = e.Message; }
        catch (CardException e) { RetainPinForRetry(); Error = true; Status = e.Message; Detail = "Allontana e riavvicina la carta per una nuova lettura. Il PIN resta disponibile finché l'app è aperta in primo piano."; }
        catch (TimeoutException) { RetainPinForRetry(); Error = true; Status = "Tempo di lettura scaduto"; Detail = "Avvicina la carta all'antenna NFC e riprova. Non occorre reinserire il PIN."; }
        catch (HttpRequestException) { RetainPinForRetry(); Error = true; Status = "Il servizio CIE non ha completato la richiesta"; Detail = "Verifica la connessione e avvia un nuovo accesso dal servizio."; }
        catch (CieQrException e) { RetainPinForRetry(); Error = true; Status = "Accesso QR non completato"; Detail = e.Message; }
        catch { RetainPinForRetry(); Error = true; Status = "Lettura interrotta"; Detail = "La carta potrebbe essere stata spostata o NFC non è accessibile. Riprova tenendola ferma."; }
        finally { FinishNfcGuide(); Array.Clear(pin); _operation = null; Busy = false; }

        void RetainPinForRetry()
        {
            // Only a manual retry can reuse it. Backgrounding/cancellation and a rejected PIN always clear it.
            if (!fromKeyring && !operation.IsCancellationRequested) Pin = new string(pin);
        }
    }

    private async Task LocateCardAsync()
    {
        if (Busy || !_nfcReady) return;
        Busy = true; Error = false; ResetNfcGuide();
        using var operation = new CancellationTokenSource(TimeSpan.FromSeconds(65));
        _operation = operation;
        try
        {
            OnProgress(CieProgress.WaitingForCard);
            await using var card = new CieCard(await _reader.WaitForCardAsync(operation.Token));
            OnProgress(CieProgress.CardDetected);
            await card.ReadServiceIdAsync(operation.Token);
            Status = "CIE riconosciuta senza PIN";
            Detail = "Questa è la posizione giusta. Puoi procedere con la lettura della carta.";
        }
        catch (OperationCanceledException) { Status = "Ricerca annullata"; Detail = "Puoi riprovare quando vuoi."; }
        catch (CardException e) { Error = true; Status = e.Message; Detail = "Allontana e riavvicina la carta."; }
        catch { Error = true; Status = "Carta non letta"; Detail = "Sposta lentamente la carta sul retro del telefono e riprova."; }
        finally { FinishNfcGuide(); _operation = null; Busy = false; }
    }

    private async Task ImportDocumentAsync()
    {
        if (!CanImportDocument || _registered is null || _profile is null || _profiles is null) return;
        char[] can = Can.ToCharArray(); Can = "";
        var profile = _profile;
        Busy = true; Error = false; ResetNfcGuide();
        using var operation = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        _operation = operation;
        var progress = new Progress<CieProgress>(p => { if (_operation == operation && !operation.IsCancellationRequested) OnProgress(p); });
        try
        {
            var document = await new IcaoDocumentReader(_reader).ReadAsync(_registered, _identity!.DocumentNumber, can, progress, operation.Token);
            operation.Token.ThrowIfCancellationRequested();
            var updated = profile with { Document = document };
            await _profiles.SaveProfileAsync(updated, operation.Token);
            SetProfile(updated);
            Status = "Dati e foto salvati";
            Detail = "Puoi consultare il documento e il certificato anche senza avvicinare la CIE.";
        }
        catch (OperationCanceledException) { Status = "Lettura del documento annullata"; Detail = "I dati salvati in precedenza sono ancora disponibili."; }
        catch (Exception e)
        {
            Error = true; Status = "Documento non importato";
            Detail = e is UTCie.Sdk.Card.CardException or CredentialStoreException ? e.Message : "Lettura ICAO interrotta. Allontana e riavvicina la carta, poi riprova.";
            if (!operation.IsCancellationRequested) Can = new string(can);
        }
        finally { Array.Clear(can); FinishNfcGuide(); _operation = null; Busy = false; }
    }

    private void SetProfile(CardProfile? profile)
    {
        _identity = profile?.GetCertificateDetails();
        _profile = profile;
        foreach (var property in new[] { nameof(HasProfile), nameof(NeedsProfile), nameof(HasDocument), nameof(NeedsDocument), nameof(Document),
            nameof(GivenName), nameof(Surname), nameof(DocumentNumber), nameof(FiscalCode), nameof(CertificateSubject), nameof(CertificateIssuer),
            nameof(CertificateValidity), nameof(CertificateSerial), nameof(CertificateFingerprint), nameof(DocumentBirth), nameof(DocumentExpiry),
            nameof(Nationality), nameof(Sex), nameof(CanImportDocument) }) Notify(property);
    }
    private static string Display(string? value) => string.IsNullOrWhiteSpace(value) ? "Non disponibile" : value;
    private static string MrzDate(string? value) => value?.Length == 6 ? $"{value[4..6]}/{value[2..4]}/{value[..2]}" : "Non disponibile";

    private void ResetNfcGuide() { _cardDetected = false; NfcGuideTitle = ""; NfcGuideDetail = ""; }

    private void FinishNfcGuide()
    {
        if (!HasNfcGuide) return;
        NfcGuideTitle = _operation?.IsCancellationRequested == true ? "Lettura annullata" : Error ? "Lettura non completata" : HasOtp ? "Codice OTP pronto" : "Puoi allontanare la carta";
        NfcGuideDetail = Error ? $"{Status}\n{Detail}" : HasOtp ? Detail : Status;
        NfcGuideColor = Error ? "#FFF0DB" : "#DDEEEB";
    }

    private async Task ForgetCardAsync()
    {
        if (Busy || _registered is null || _credentials is null) return;
        Busy = true;
        using var operation = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        _operation = operation;
        try
        {
            if (_profiles is not null) await _profiles.DeleteProfileAsync(_registered, operation.Token);
            await _credentials.ForgetAsync(_registered, operation.Token);
            _registered = null; Pin = ""; Can = ""; Certificate = ""; SetProfile(null); SelectedTab = 0; ClearCompletion(); RegistrationChanged();
            Status = "Carta e PIN rimossi"; Detail = "Dati, foto, certificato e PIN sono stati rimossi dal portachiavi."; Error = false;
        }
        catch (CredentialStoreException e) { Error = true; Status = "Rimozione non completata"; Detail = e.Message; }
        catch (OperationCanceledException) { Status = "Rimozione annullata"; }
        catch { Error = true; Status = "Rimozione non completata"; Detail = "Non è stato possibile aggiornare la registrazione."; }
        finally { _operation = null; Busy = false; }
    }

    private void RegistrationChanged()
    {
        Notify(nameof(HasRegistration)); Notify(nameof(NeedsProfile)); Notify(nameof(EnterPin)); Notify(nameof(CanContinue)); Notify(nameof(CanRegister));
    }

    private void OnProgress(CieProgress progress)
    {
        if (progress == CieProgress.WaitingForCard)
        {
            NfcGuideTitle = "Cerca la carta";
            NfcGuideDetail = "Spostala lentamente sul retro. Quando vibra, fermati.";
            NfcGuideColor = "#E4EEF8";
        }
        else if (progress == CieProgress.CardDetected && !_cardDetected)
        {
            _cardDetected = true;
            NfcGuideTitle = "Carta rilevata: tienila ferma";
            NfcGuideDetail = "NFC ha agganciato la carta. Mantieni questa posizione fino al termine.";
            NfcGuideColor = "#C7EEDC";
            CardDetected?.Invoke();
        }
        Status = progress switch
        {
            CieProgress.WaitingForCard => "Avvicina la CIE al telefono",
            CieProgress.CardDetected => "Carta rilevata",
            CieProgress.OpeningSecureChannel => "Verifica del chip e del PIN…",
            CieProgress.ReadingCertificate => "Lettura del certificato…",
            CieProgress.OpeningDocument => "Apertura del documento con il CAN…",
            CieProgress.ReadingDocument => "Lettura dei dati e della foto…",
            CieProgress.RequestingChallenge => "Connessione al servizio CIE…",
            CieProgress.Signing => "Firma della richiesta…",
            CieProgress.AuthenticatingTls => "Autenticazione della CIE al servizio…",
            CieProgress.ReceivingOtp => "Ricezione del codice OTP…",
            _ => Status
        };
        Detail = "Mantieni la carta ferma fino al termine dell'operazione.";
    }

    private async Task OpenBrowserAsync()
    {
        if (_completion is null || OpenUriAsync is null) return;
        try
        {
            if (!await OpenUriAsync(_completion)) { Status = "Impossibile aprire il browser."; Error = true; }
        }
        catch { Status = "Impossibile aprire il browser."; Error = true; }
    }
    public void Cancel() => _operation?.Cancel();
    public void OnDeactivated()
    {
        Cancel(); Pin = ""; Can = ""; Certificate = ""; Otp = "";
    }
    private void ClearCompletion() { _completion = null; Otp = ""; Notify(nameof(HasCompletion)); }
    private (CieAuthenticationRequest? Mobile, CieQrAuthenticationRequest? Qr) ParseRequest() => IsQrRequest
        ? (null, CieQrAuthenticationRequest.Parse(RequestLink, (CieEnvironment)EnvironmentIndex))
        : (CieAuthenticationRequest.Parse(RequestLink.Trim(), (CieEnvironment)EnvironmentIndex), null);

    private async Task ScanQrAsync()
    {
        if (Busy || ReadCameraQrAsync is null) return;
        string? link = null;
        ClearCompletion(); ResetNfcGuide(); Error = false; Busy = true; ScanningQr = true;
        Status = "Inquadra il QR CIE";
        Detail = "Inquadra il codice sul computer con la fotocamera posteriore.";
        using var operation = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        _operation = operation;
        try
        {
            link = await ReadCameraQrAsync(operation.Token);
            operation.Token.ThrowIfCancellationRequested();
        }
        catch (OperationCanceledException) { link = null; Status = "Scansione terminata"; Detail = "Premi «Scansiona QR» per inquadrare nuovamente il codice."; }
        catch (Exception e)
        {
            link = null; Error = true; Status = "Fotocamera non disponibile";
            Detail = e is QrScanException ? e.Message : "Non è stato possibile avviare la scansione. Chiudi le altre app che usano la fotocamera e riprova.";
            NfcGuideTitle = Status; NfcGuideDetail = Detail; NfcGuideColor = "#FFF0DB";
        }
        finally { ScanningQr = false; _operation = null; Busy = false; }
        if (link is not null)
        {
            AcceptQrLink(link);
            if (!Error)
            {
                Status = "QR riconosciuto";
                Detail = "Controlla il servizio, premi «Genera codice OTP» e avvicina la CIE.";
                NfcGuideTitle = Status; NfcGuideDetail = Detail; NfcGuideColor = "#DDEEEB";
            }
        }
    }

    public void AcceptQrLink(string link)
    {
        if (Busy) return;
        ApplyLink(link);
        if (!Error) { Status = "Richiesta pronta"; Detail = "Controlla il servizio, premi il pulsante di accesso e avvicina la CIE."; }
    }
    private void ShowRequestError(ArgumentException error)
    {
        Status = error.Message;
        Detail = error is CieUnsupportedFlowException unsupported
            ? unsupported.Guidance : IsQrRequest ? "Controlla il QR e la carta selezionata nel sito del servizio." : "Richiedi un nuovo collegamento OpenApp dal servizio.";
        Error = true;
        NfcGuideTitle = "Richiesta di accesso non valida";
        NfcGuideDetail = $"{Status}\n{Detail}";
        NfcGuideColor = "#FFF0DB";
    }
    private void ApplyLink(string link)
    {
        Error = false;
        try
        {
            if (link.StartsWith("utcieid://", StringComparison.Ordinal))
            {
                var uri = new Uri(link);
                if (uri.Host != "authenticate" || !uri.Query.StartsWith("?url=", StringComparison.Ordinal)) throw new ArgumentException();
                link = Uri.UnescapeDataString(uri.Query[5..]);
            }
            var host = new Uri(link).IdnHost;
            EnvironmentIndex = host.StartsWith("collaudo.", StringComparison.Ordinal) ? 2 : host.StartsWith("preproduzione.", StringComparison.Ordinal) ? 1 : 0;
            RequestLink = link; SelectedTab = 1;
            ParseRequest();
        }
        catch (ArgumentException e) { ShowRequestError(e); }
        catch { Status = "Link CIE non valido."; Error = true; }
    }
    private bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    { if (EqualityComparer<T>.Default.Equals(field, value)) return false; field = value; Notify(name); return true; }
    private void Notify([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new(name));

    private sealed class ActionCommand(Action action) : ICommand
    {
        public event EventHandler? CanExecuteChanged { add { } remove { } }
        public bool CanExecute(object? parameter) => true;
        public void Execute(object? parameter) => action();
    }
    private sealed class AsyncCommand(Func<Task> action) : ICommand
    {
        private bool _running;
        public event EventHandler? CanExecuteChanged;
        public bool CanExecute(object? parameter) => !_running;
        public async void Execute(object? parameter)
        {
            if (_running) return;
            _running = true; CanExecuteChanged?.Invoke(this, EventArgs.Empty);
            try { await action(); }
            finally { _running = false; CanExecuteChanged?.Invoke(this, EventArgs.Empty); }
        }
    }
}

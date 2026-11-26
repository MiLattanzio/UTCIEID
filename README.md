# UTCIEID

Client CIE indipendente per Ubuntu Touch, con SDK C# e frontend Avalonia in AXAML.
Il protocollo è derivato dall'SDK Android IPZS; non è l'app ufficiale CieID.

## Stato

Anteprima di sviluppo per Ubuntu Touch 24.04 ARM64. Sono implementati selezione
IAS/CIE, canale DH/DAPP, secure messaging, verifica PIN, lettura del certificato,
firma della challenge OpenApp, continuazione nel browser e flusso QR di livello 3
con OTP e autenticazione TLS tramite la carta. La registrazione salva
il PIN completo nel portachiavi persistente di sistema, su richiesta dell'utente.
Il tab **Dati** conserva anche anagrafica e certificato DER completo; la foto e i
dati ICAO si importano con il CAN stampato sul documento.

La lettura del certificato e la registrazione con PIN completo nel portachiavi sono
state verificate con una CIE reale su Fairphone 5, con AppArmor attivo. È stato
verificato anche il riuso del PIN dal portachiavi dopo chiusura e riapertura dell'app,
oltre al canale DH/DAPP senza inviare PIN. Il nuovo tab Dati e l’importazione
della foto tramite PACE DH/CAN sono stati verificati sulla stessa CIE reale;
foto, anagrafica e certificato sono rimasti disponibili dopo il riavvio dell’app.
Il flusso QR di livello 3 è stato verificato fino all'accesso reale a MyINPS:
firma NFC, autenticazione TLS della carta, OTP nell'app e conferma nel browser.
La scansione dalla fotocamera è stata verificata sullo stesso telefono con un QR
CIE sintetico: anteprima, consenso standard, messa a fuoco, riconoscimento e
chiusura della fotocamera riusciti sotto AppArmor.
Il flusso OpenApp deve ancora essere verificato con una richiesta reale.
Vedere [verifiche e limiti](docs/verification.md).

La [privacy dell'app](docs/privacy.md) descrive conservazione locale e dati
trasmessi per l'autenticazione. Le [schermate dimostrative](packaging/openstore/screenshots/)
sono generate dall'AXAML con dati sintetici e non contengono dati personali reali.

## Uso

1. Attiva NFC e apri **Trova la CIE (senza PIN)**. Sposta lentamente la carta sul
   retro: una vibrazione e **Carta rilevata: tienila ferma** segnalano l'aggancio.
   L'avviso resta sopra il contenuto durante la lettura.
2. Inserisci il PIN di otto cifre e lascia selezionata la registrazione, poi premi
   **Leggi la tua CIE**. Il PIN è salvato soltanto dopo una lettura riuscita.
3. Con la carta registrata, **Usa il PIN dal portachiavi** evita di reinserirlo.
   Nel nuovo tab **Dati** trovi nome, cognome, numero del documento, codice fiscale
   e certificato (intestatario, emittente, validità, seriale, impronta SHA-256).
   Per le registrazioni precedenti, premi **Importa dati e certificato** una volta.
   Per la foto inserisci il **CAN di 6 cifre** nel tab Dati, premi **Importa foto e
   dati** e mantieni ferma la carta. Il CAN non viene salvato e questa operazione
   non usa il PIN. **Dimentica carta, dati e PIN** elimina tutti i dati salvati.
4. Per l'accesso da computer, scegli sul sito **Entra con lettura carta** e
   **Prosegui con smartphone**. Nel tab **Accedi**, premi **Scansiona QR** e inquadra
   il codice di livello 3 con la fotocamera posteriore. Consenti l'accesso alla
   fotocamera se richiesto; se il QR è sfocato, tocca il centro dell'anteprima.
   Dopo il riconoscimento,
   premi **Genera codice OTP** e avvicina la CIE. Riporta l'OTP nella pagina
   del computer. Sono supportati anche i link HTTPS `/idp/OpenApp`, che continuano
   nel browser dopo la firma. Il flusso è descritto in [QR e OTP](docs/qr-otp.md).

I QR di livello 2 richiedono la certificazione del dispositivo e non sono supportati.
La scansione usa la fotocamera posteriore, con anteprima in memoria. Le immagini
non vengono salvate. La fotocamera si chiude dopo il riconoscimento, annullando la
scansione o passando in background. Il pulsante di importazione immagini è stato rimosso.

Un errore NFC conserva il PIN inserito per il successivo tentativo manuale finché
l'app resta in primo piano. Un PIN rifiutato, l'annullamento della lettura o il
passaggio in background lo cancellano dalla UI. Nessun tentativo fallito di verifica
PIN viene ripetuto automaticamente. Prima di usare il PIN salvato viene confrontato
l'hash dell'identificativo della carta con quello registrato.

Il riconoscimento NFC non implica ancora che la carta sia stata autenticata.
Il pulsante senza PIN legge solo il file servizi e non registra una carta.

## Dati del documento e compatibilità ICAO

La CIE ha applicazioni IAS e ICAO distinte. Il certificato si legge con il PIN;
DG1 (MRZ) e DG2 (volto) si leggono tramite PACE con CAN. Il codice C# implementa
PACE v2 DH/ECDH Generic Mapping con gruppi/curve standard, 3DES/AES, lettura a blocchi,
verifica della firma SOD e degli hash di DG1/DG2. Il numero del documento deve
corrispondere al certificato già registrato. Non sono ancora implementati PACE IM/CAM, BAC/MRZ nell'interfaccia né la catena di fiducia CSCA o Chip Authentication.
Non si presenta questa verifica parziale come certificazione dell'autenticità.

Le **impronte non sono accessibili alle normali app**: richiedono le autorizzazioni
delle autorità di controllo. Il lettore esclude DG3/DG4. JMRTD implementa gli stessi
standard in Java; questa app usa codice C# e non richiede JVM o Android.
JPEG è decodificato da Avalonia; JPEG 2000 da un piccolo adattatore alla libreria
OpenJPEG di Ubuntu Touch. I dettagli sono in [docs/card-data.md](docs/card-data.md).

## Compilazione

Requisiti: .NET SDK **10.0.404**, Linux, `dbus-daemon` per il test di trasporto;
Docker con l'immagine `clickable/amd64-ut24.04-2.x-arm64:latest` per il pacchetto Click;
ADB per il dispositivo. Il progetto usa direttamente il fork Avalonia con supporto
Maliit e ContentHub, senza dipendenza runtime da UTDotNet.

Checkout Avalonia atteso: `../Avalonia`, fork
[MiLattanzio/Avalonia](https://github.com/MiLattanzio/Avalonia), commit
`96f29a622ca10e904fc8373e1e6e4c6d04662877`. Nell'ambiente verificato il submodule
`external/Avalonia.DBus` è al commit `e793254ddaaa51af327a5840d7738de2d18eb865`.
Inizializzare anche gli altri submodule del fork. Per un altro percorso passare
`-p:AvaloniaSourceRoot=/percorso/Avalonia`.

Applicare al fork la patch inclusa per l'attivazione iniziale XMir (già applicata
nel workspace di sviluppo):

```sh
git -C ../Avalonia apply --check ../UTCIEID/patches/avalonia-x11-initial-activation.patch
git -C ../Avalonia apply ../UTCIEID/patches/avalonia-x11-initial-activation.patch
```

Ripristina lo stato corrente della finestra quando la prima notifica precede la
sottoscrizione o cambia il metodo di rilevamento del window manager. Evita che
Maliit resti chiuso nonostante il campo PIN abbia il focus.

```sh
dotnet test tests/UTCie.Tests/UTCie.Tests.csproj -c Release --disable-build-servers -m:1
dotnet build src/UTCIEID.App/UTCIEID.App.csproj -c Release --disable-build-servers -m:1
./scripts/build-click.sh
./scripts/install-device.sh
```

Il pacchetto è `artifacts/click/utcieid.milattanzio_0.2.0_arm64.click`.
Il launcher predefinito usa X11/XMir. `UTCIEID_BACKEND=wayland` seleziona il backend
Wayland; questa app è stata provata sul telefono con X11.
`-p:UseAvaloniaSource=false` usa i pacchetti Avalonia 12.1.6 per sviluppo desktop,
senza garantire le integrazioni Ubuntu Touch presenti nel fork.

## Portachiavi su Ubuntu Touch

Il profilo Click standard consente NFC e rete, ma non Secret Service. La funzione
richiede l'estensione specifica descritta in [portachiavi](docs/keyring.md).
Se il servizio è bloccato o indisponibile, il PIN non viene salvato in un file come
fallback. L'app resta confinata da AppArmor anche con l'estensione.

## Struttura e licenze

| Percorso | Funzione |
| --- | --- |
| `src/UTCie.Sdk` | Protocollo carta, crittografia, richieste di autenticazione |
| `src/UTCie.Linux` | nfcd, libsecret, apertura browser e feedback aptico Lomiri |
| `src/UTCIEID.App` | Interfaccia AXAML e stato dell'app |
| `tests/UTCie.Tests` | Vettori crittografici, simulatore carta, D-Bus e regressioni |
| `packaging` e `scripts` | Click ARM64 e regola opzionale del portachiavi |

La derivazione IPZS usa BSD-3-Clause; le attribuzioni Avalonia e Tmds.DBus sono in
`licenses/`, insieme agli avvisi di .NET, SkiaSharp, HarfBuzzSharp, Inter e delle
altre dipendenze distribuite. La [mappa del porting](docs/porting.md) descrive
corrispondenze e scelte.

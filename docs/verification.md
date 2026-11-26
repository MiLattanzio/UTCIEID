# Verifiche di sviluppo

Dispositivo: Fairphone 5 ARM64, Ubuntu Touch 24.04.5, connessione USB/ADB.
Backend UI provato: X11/XMir con il fork Avalonia e Maliit integrato.

## Risultati osservati

- Compilazione dai sorgenti Avalonia e pacchetto Click ARM64 self-contained riusciti.
- Avvio confinato e stato NFC disponibile tramite `org.neard`.
- Campo PIN mascherato, tastiera Maliit e contenuto portato sopra l'area coperta.
- Carta reale: IAS `6A82`, selezione CIE `9000`, selezione file servizi `9000`,
  lettura `9000` con 12 byte. Prova senza PIN, dati identificativi omessi.
- Carta reale: preparazione del canale DH/DAPP completa, con verifica del MAC e
  della prova del chip, terminata prima di VERIFY PIN. Il trasporto diagnostico
  vieta esplicitamente INS `20` e stampa solo header, status e lunghezze.
- Carta reale: lettura del certificato e salvataggio del PIN completo nel portachiavi
  riusciti; esito «CIE registrata» osservato e confermato dall'utente.
- Dopo chiusura e riapertura: registrazione ripristinata, campo PIN nascosto, opzione
  portachiavi attiva. L'utente ha confermato una nuova lettura riuscita della stessa
  carta senza reinserire il PIN.
- Secret Service: salvataggio, lettura e cancellazione di un segreto sintetico
  riusciti sotto il profilo UTCIEID in modalità enforce con l'estensione autorizzata.
- Breve vibrazione HFD consentita dal profilo standard e comando eseguito sul telefono.
- Nuova UI installata: avviso «Cerca la carta» verificato sopra il contenuto durante
  la ricerca senza PIN. Correzioni di selezione IAS e riuso PIN incluse nel pacchetto.
- 78 test automatici superati, zero fallimenti. Pacchetto aggiornato SHA-256:
  `7fbbcb75b113228c02586e5546a6c70f70603d6f8176d593fddf34481415ff6c`.

## Test automatici

La suite include APDU/TLV malformati, vettore DES noto, vettore ICAO secure messaging,
MAC alterati, contatori per sessione, status PIN unsigned, catene GET RESPONSE,
correzione Le, selezione IAS opzionale, limiti HTTP e validazione OpenApp.
Il simulatore verifica MAC e prova del terminale, completa il canale DH/DAPP,
genera un certificato RSA e firma una challenge verificata dal client.
Non simula la policy di fiducia della CA del produttore della carta.

Un daemon D-Bus privato verifica realmente discovery, acquisizione, parametri
NDEF, serializzazione `yyyyayu`, risposte `ayyy` e distinzione Le assente/256.
Le regressioni della registrazione coprono PIN errato, carta diversa, errore del
portachiavi, cancellazione e conservazione del PIN per un tentativo manuale.

## Prove ancora necessarie

- Autenticazione completa con una richiesta OpenApp reale e ritorno al servizio.
- Backend Wayland di questa app e altri modelli/revisioni di CIE.

### Primo tentativo QR INPS, prima del supporto OTP (26 novembre 2026)

Decodificati localmente un QR di livello 2 (`/idp/login/livello2QR`) e il QR
«computer + smartphone» di livello 3 (`/idp/erroreQr.jsp`, `opType=login`).
La pagina ufficiale richiede per il secondo un OTP da riportare nel browser.
Nessuno dei due è una richiesta OpenApp: il flusso OTP non era implementato dal
porting e l'accesso INPS **non è stato completato**. Nessun PIN è stato
inviato alla carta e nessuna challenge è stata firmata per questi QR.

La costante `Authn/SSL/X509AuthIbridoTLS13` presente nell'SDK Android non è
utilizzata dal servizio Retrofit: da sola non documenta il protocollo QR.
Non viene quindi inventata una conversione di `opId` in un link OpenApp.
L'interfaccia ora distingue i flussi non supportati dai link malformati e mantiene
il messaggio dopo il controllo NFC iniziale. Le regressioni verificano che un QR
non acceda al PIN salvato né esegua VERIFY PIN; nessun parametro reale è nei test.

116 test superati. Aggiornamento Click installato; hash della DLL SDK sul telefono
corrispondente alla build locale. Estensione Secret Service già autorizzata
ripristinata e prova confinata con PIN/certificato sintetici riuscita, senza
modificare la registrazione reale. SHA-256 del pacchetto:
`0a15681f7c6063abf55df3babe65decd68064e1ef26ead8db88ea39c01784729`.

Riferimento ufficiale del flusso:
[guida CIE per Android](https://idserver.servizicie.interno.gov.it/idp/tutorial_android.jsp).

### Implementazione QR con OTP e seconda prova INPS (26 novembre 2026)

Implementato il protocollo ibrido descritto in [qr-otp.md](qr-otp.md), con firma
del QR esatto, TLS 1.2 autenticato dalla carta e risposta OTP. La suite comprende
160 test superati, inclusi handshake TLS con firmatario esterno, verifica della
fiducia del server, firma doppia sulla stessa sessione CIE simulata, limiti HTTP,
lettura PNG/JPEG e pulizia dell'OTP in background.

Il primo tentativo con questa implementazione si è fermato nella validazione
locale: il QR ufficiale contiene spazi ASCII letterali in `opText`. Il controllo
troppo restrittivo è stato corretto mantenendo intatta la stringa firmata. Nessun
PIN è stato inviato in quel tentativo. La regressione usa un QR sintetico.
Il QR reale inviato dall'utente viene ora decodificato e validato sul Fairphone
dal comando `--probe-qr-file`, sotto AppArmor enforce, senza rete o NFC.

Il pulsante principale è fisso in basso e l'OTP compare nell'avviso in alto.
La verifica confinata del portachiavi con dati sintetici è riuscita; registrazione,
foto e certificato reali sono stati conservati. Pacchetto installato SHA-256:
`3eae8ceb3ce1c9157e4b38fb5add7f050ecc9d627106e86f92ee7b6eea3b19f9`.

La prova successiva ha completato apertura del canale con il PIN salvato, lettura
del certificato e firma del QR reale, verificata localmente. Si è fermata perché
l'host principale non richiede il certificato TLS client. Una richiesta pubblica
senza dati personali al percorso ufficiale ha restituito HTTP 307 verso
`https://mtls.idserver.servizicie.interno.gov.it/idp/Authn/SSL/X509AuthIbrido`.
Verificati catena e hostname del server dedicato e la richiesta CertificateRequest
con RSA/SHA-256. Il client di produzione usa ora direttamente quell'host fisso.

161 test superati e nuova build installata; portachiavi sintetico verificato sotto
AppArmor enforce. SHA-256:
`77e8e0b43ba9f8462eda0b01247bf893f8c80c2eeae46f0d00b4dc6a668b3bf1`.
La prova finale è **riuscita fino all'accesso a MyINPS**. L'utente ha confermato
la ricezione dell'OTP nell'app e il proseguimento del browser dopo averlo inserito.
È stato osservato il ritorno autenticato a INPS; selezionato «Prosegui per il
servizio richiesto», è comparsa la bacheca personale MyINPS. Non sono stati
modificati contatti, consensi o altri dati del profilo INPS.

Verificati quindi sulla CIE reale: recupero del PIN registrato, firma esatta del
QR, seconda firma per TLS sullo stesso canale della carta, ricezione dell'OTP e
accesso federato completo. Le copie temporanee del QR usate per il trasferimento
al telefono sono state rimosse. Il test non copre fotocamera, selettore file
tramite Content Hub o altre CIE/ambienti.

### Fotocamera QR (26 novembre 2026)

La versione 0.2.0 sostituisce **Importa immagine QR** con **Scansiona QR**.
L'interfaccia resta Avalonia/AXAML; il worker libhybris fornisce l'anteprima in
memoria e il decoder C# legge i fotogrammi senza salvare immagini.

- Worker sul Fairphone 5: fotogrammi 1280×960, orientamento 90°, chiusura regolare.
- La prima prova confinata non mostrava il permesso: mancava una sessione Mir
  del worker e il servizio permessi era rimasto bloccato. Aggiunta la sessione,
  riavviato il solo servizio e riprovato come figlio dell'app aperta dal launcher.
- Dialogo standard con consenso concesso dall'utente; riuso del consenso
  osservato nel servizio di sistema. Nessuna modifica al database dei permessi.
- L'utente ha confermato l'anteprima nell'app confinata, ma il QR era sfocato.
  La build successiva usa autofocus continuo per foto, autofocus iniziale e
  rifocalizzazione toccando l'anteprima. L'utente ha confermato **QR riconosciuto**
  inquadrando un QR CIE sintetico sul computer, senza importare immagini.
- Dopo il riconoscimento il worker non era più presente: rilascio della
  fotocamera verificato. La prova non ha usato NFC, PIN o rete e non ha generato
  un OTP. L'accesso INPS completo era già stato verificato con il medesimo
  flusso QR/OTP prima dell'aggiunta della fotocamera.
- 182 test passati: framing, dimensioni, orientamento, QR a quattro rotazioni,
  nessun VERIFY PIN durante la scansione, annullamento e scarto di risultati
  tardivi, chiusura di processi bloccati, rifocalizzazione senza interrompere
  l'acquisizione. Build AXAML e C con `-Wall -Wextra -Werror` riuscite.
- Aggiornamento installato, processo sotto AppArmor enforce; accesso al
  portachiavi ripristinato e prova con PIN/certificato sintetici riuscita.

SHA-256 del pacchetto con correzione autofocus:
`f02a62e92f532f4b80d4a8d9281518e74e75d15b30e5fe00eec0212c0cdf3afb`.
Dettagli e fonti in [camera.md](camera.md).

## Ambito dell'anteprima

Non comprende recupero PIN, sblocco PUK, notifiche push o accesso alle impronte
digitali. La scansione QR dalla fotocamera e il flusso OTP sono descritti in
[qr-otp.md](qr-otp.md); l'importazione di immagini è rimossa dall'interfaccia.
Il link `utcieid://authenticate?url=<OpenApp codificato>` è gestito all'avvio; la
consegna di nuovi link a un processo già aperto non è ancora implementata. È
possibile incollare il link nella scheda Accedi.
Non è stato svolto un audit indipendente né una certificazione IPZS del porting.

## Problemi riprodotti e correzioni

La CIE reale è stata riconosciuta anche dal pulsante «Trova la CIE (senza PIN)»
dell'app installata: avviso finale osservato «CIE riconosciuta senza PIN».

Dopo una reinstallazione, XMir pubblicava `_NET_ACTIVE_WINDOW` con l'XID corretto,
ma Avalonia restava inattivo e non apriva Maliit. Una nuova notifica della stessa
finestra ripristinava immediatamente la tastiera. La patch in `patches/` fa leggere
lo stato corrente alla sottoscrizione e al cambio della modalità di attivazione.
La build con questa patch è stata installata. Verificati l'apertura della tastiera
dopo un avvio pulito e il ritorno al campo PIN dopo il riconoscimento reale della
CIE. L'area del contenuto si riduce correttamente e il PIN resta visibile sopra
la tastiera. Nessuna modifica manuale alle proprietà X11 è necessaria nella build
corretta. Il portachiavi sintetico è stato verificato di nuovo con esito positivo.

La prima lettura con PIN si è interrotta con `SW 6B00`. La preparazione del canale
senza PIN ha poi confermato il funzionamento delle fasi precedenti a VERIFY PIN.
Nel confronto con `getRespSM` Android è emersa la necessità di accettare gli
involucri di fine-file `6282`/`6B00`: il porting ora richiede comunque MAC valido
e status DO99 coerente con quello esterno. Coperti da test anche MAC alterati,
status incoerenti, assenza di DO99 e lettura completa con fine-file separato.
La build corretta ha letto il certificato reale e completato la registrazione.

## Tab Dati e importazione ICAO (26 novembre 2026)

- 109 test passati: campi X.500 per OID, persistenza esatta DER, migrazione delle
  registrazioni precedenti, riapertura offline e rimozione del profilo.
- Vettori PACE ECDH-GM e DH-GM AES-128 (ICAO appendici G.1 e G.2),
  APDU estese tramite nfcd/D-Bus, validazione dei sottogruppi DH, secure
  messaging ICAO, selezione del riferimento CAN, rifiuto di algoritmi sconosciuti,
  TLV malformati, firma SOD e hash di DG1/DG2 (inclusa alterazione dei dati).
- JPEG 2000 sintetico RGB e scala di grigi: dimensioni e pixel decodificati esatti.
- Build Click con helper nativo ARM64 riuscita. Tab Dati visibile sulla registrazione
  esistente. Prova libsecret nel profilo AppArmor enforce: PIN e certificato sintetici
  salvati con attributi separati, riletti e rimossi; registrazione reale non modificata.
- L’utente ha confermato la lettura reale di nome, cognome e certificato nel nuovo
  tab Dati. La carta dichiara PACE DH-GM-3DES, dominio RFC 5114 2048/256 (ID 2).
  Aggiunto il supporto DH e corretta la sequenza ICAO prima di IAS. L’utente ha
  confermato la comparsa della foto reale dopo l’importazione con CAN.
  Dopo chiusura e riapertura, l’utente ha confermato foto, anagrafica e certificato
  presenti senza carta né inserimento di codici. Persistenza reale verificata.
- Sessione CAN completa su chip simulato con 3DES, AES-128, AES-192 e AES-256,
  lettura dei data group e firma SOD verificate.
- Catena CSCA, Chip Authentication e altre varianti PACE non verificate/implementate.

La prova su carta reale ha mostrato che SELECT CIE seguito da SELECT MF nasconde
CardAccess (6A82). Il lettore ICAO esegue ora PACE e lettura LDS prima del controllo
finale dell’identificativo servizi IAS. Coperto da una regressione della sequenza
APDU. Per avviare una nuova importazione si allontana e riavvicina la carta.

Pacchetto con importazione reale della foto riuscita: SHA-256
`890a4d7ec4b7066515930f6e3161d2f385ed06609118c4982deed8523f253561`.

## Pacchetto preparato per OpenStore (26 novembre 2026)

La build 0.2.0 include tutte le funzioni già provate, le licenze dei componenti
incorporati e non contiene i simboli PDB. La suite completa ha superato
182 test, senza fallimenti. Sono stati controllati i file dell'archivio Click:
nessuna registrazione, chiave privata, schermata o fixture dimostrativa inclusa.

Installata sul Fairphone 5 ricollegato via ADB; avvio riuscito e processo sotto
AppArmor `enforce`. Ripristinata la stessa estensione Secret Service già
autorizzata per il solo profilo UTCIEID. La prova del portachiavi con PIN e
certificato sintetici è riuscita, senza modificare la registrazione reale.
L'hash del pacchetto trasferito coincide con quello locale:
`0347bdb3b068d053d3eec87bf218be772f216d9eb0cec9e0ebfe283bcca2b281`.

Questa verifica sul dispositivo di sviluppo non risolve la distribuzione del
permesso aggiuntivo: il Click standard non installa l'estensione del portachiavi.
La revisione OpenStore deve stabilire una modalità accettata prima della
pubblicazione della versione completa.

Corretto poi il solo campo maintainer nel formato richiesto da OpenStore, con
nome e indirizzo indicati dall'utente. Il pacchetto definitivo è stato installato
e la prova sintetica del portachiavi ha avuto nuovamente esito positivo sotto
AppArmor enforce. Il controllo automatico OpenStore è stato superato:
`fdde5cced54412ce9026bb64502b23ec60e87d1deb973504d5a1a95bb27f30b3`.
Questo esito riguarda il profilo Click standard e non approva l'estensione
Secret Service richiesta per la distribuzione completa.

# Scansione QR dalla fotocamera

La UI è Avalonia/AXAML. **Scansiona QR**, nel tab **Accedi**, apre un'anteprima
della fotocamera posteriore e legge il QR direttamente dai fotogrammi. L'anteprima
è in scala di grigi: usa lo stesso piano di luminanza impiegato dal decoder.
La rotazione dichiarata dal sensore è applicata alla visualizzazione; il decoder
supporta anche QR ruotati. Non è necessario importare immagini o aprire altre app.
La messa a fuoco usa la modalità continua per foto, con un primo autofocus dopo
l'avvio. Toccando l'anteprima si ripete l'autofocus; dopo tre secondi il blocco
viene rilasciato per seguire nuovamente la distanza del telefono.

`native/camera.c` è un piccolo processo separato, compilato nel Click ARM64 come
`app/utcieid-camera`. Usa l'ABI C della libreria di sistema `libcamera.so.1`
(libhybris) e una superficie EGL pbuffer con texture esterna Android. La superficie
è necessaria per avviare il flusso di anteprima del driver. Il worker usa il vendor
EGL libhybris indipendentemente dal renderer del processo Avalonia.
Il worker apre anche una connessione Mir con l'identificativo dell'app: il servizio
permessi della fotocamera individua il processo richiedente tramite quella sessione.
Una sola superficie EGL fuori schermo non basta; il servizio segnalava
«Could not identify Mir session associated with pid». La connessione non crea
una seconda interfaccia o una finestra visibile.

La richiesta di permesso va provata avviando il worker come figlio dell'app
aperta dal launcher: un processo diagnostico avviato separatamente da ADB non
riproduce l'associazione fra sessione e finestra dell'app. Durante lo sviluppo
il servizio `cameraservice-trust-stored.service` era rimasto bloccato dopo
l'errore di sessione mancante; il solo servizio è stato riavviato. Nessuna voce
del database dei consensi è stata modificata. Il dialogo normale ha poi ottenuto
il consenso dell'utente e le scansioni successive lo hanno riutilizzato.

I callback forniscono fotogrammi NV21; il solo piano Y8 è inviato al processo C#
attraverso una pipe, con dimensioni e orientamento verificati e limite di
1280×960. È mantenuto un solo fotogramma recente nel worker. La pipe applica
backpressure senza accumulare immagini. `QrCameraScanner` usa ZXing per il
riconoscimento e non interpreta il risultato come comando: viene applicata la
normale validazione delle richieste CIE prima di qualsiasi accesso al PIN o a NFC.

Il processo eredita il profilo AppArmor dell'app. Il manifest 0.2.0 aggiunge il
gruppo standard `camera`; l'estensione Secret Service già autorizzata resta
separata. Non sono richiesti accesso alla galleria, microfono o privilegi root
per acquisire fotogrammi. L'aggiornamento non cambia gli attributi del portachiavi.

Quando il QR è letto, si preme **Annulla scansione**, scadono 90 secondi o l'app
passa in background, il client chiude stdin del worker e attende la disconnessione
della fotocamera. Se il driver non risponde, termina il worker dopo due secondi.
Si termina esclusivamente il processo figlio; non si enumera `/proc` per cercare
altri processi, operazione incompatibile con il confinamento standard delle app.
L'isolamento mantiene reattiva l'interfaccia anche se il driver si blocca.
L'anteprima viene rimossa e i buffer C# temporanei azzerati. Nessun fotogramma o
contenuto QR viene salvato nei file o nei log.
Il primo fotogramma ha un limite di 60 secondi per consentire la risposta al
dialogo dei permessi; i successivi hanno un limite di sei secondi. Il comando
di rifocalizzazione è un singolo byte sulla pipe di controllo e non chiude la
scansione. I tocchi ravvicinati vengono accorpati.

## API e verifiche

- [ABI fotocamera libhybris](https://github.com/ubports/libhybris/blob/xenial/hybris/include/hybris/camera/camera_compatibility_layer.h)
- [Parametri e orientamento](https://github.com/ubports/libhybris/blob/xenial/hybris/include/hybris/camera/camera_compatibility_layer_capabilities.h)
- [Componente fotocamera UBports](https://gitlab.com/ubports/core/qtubuntu-camera)
- [Permesso camera di Ubuntu Touch](https://docs.ubports.com/en/latest/appdev/platform/apparmor.html#camera)

Il test del worker sul Fairphone 5 ha ricevuto fotogrammi 1280×960, orientamento
90°, e verificato uscita regolare dopo la chiusura della pipe. I test automatici
coprono framing e limiti, rotazione, QR con spazi letterali a quattro orientamenti,
annullamento in background, rifiuto di QR estranei e chiusura effettiva di un
processo di acquisizione sintetico, anche se ignora la chiusura della pipe.
La prova dell'app confinata ha riconosciuto un QR CIE sintetico inquadrato sul
computer, con conferma dell'utente. Dopo il riconoscimento il worker si è chiuso.
182 test passati; esiti e hash del pacchetto in [verification.md](verification.md).

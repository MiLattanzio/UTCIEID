# Privacy di UTCIEID

UTCIEID è un client indipendente e non è l'app ufficiale CieID. Non include
telemetria, pubblicità o un server del progetto che raccolga i dati della carta.

## Dati sul dispositivo

- Puoi usare il PIN manualmente, senza creare un archivio. Dati, certificato e foto
  letti restano nella sessione e vengono rimossi dall'interfaccia quando lasci
  l'app. Nessun PIN viene salvato automaticamente.
- Puoi creare un archivio cifrato nella cartella privata dell'app e conservare dati,
  certificato e foto. Il salvataggio del PIN completo è una scelta separata,
  inizialmente disattivata. Avviene solo dopo una lettura riuscita.
- L'archivio usa AES-256-GCM e una chiave derivata dalla passphrase con Argon2id
  (64 MiB, tre iterazioni). La passphrase non viene salvata. L'archivio si blocca
  alla perdita del primo piano e alla chiusura. Serve sbloccarlo di nuovo per
  consultare i dati o usare il PIN salvato.
- Non possiamo recuperare una passphrase dimenticata: puoi eliminare l'archivio
  e rileggere la carta. Usa una passphrase robusta, distinta dal PIN.
- Il CAN serve solo per importare foto e dati ICAO e non viene salvato.
  La chiave privata resta nel chip. Le impronte digitali non vengono lette.
- **Rimuovi solo il PIN salvato** conserva gli altri dati. **Dimentica carta, dati
  e PIN** rimuove la registrazione dall'archivio. **Elimina archivio…** rimuove il
  file cifrato dopo una seconda conferma, anche se la passphrase è dimenticata.
  Non si garantisce l'eliminazione fisica da memoria flash, backup o copie esterne.

La versione OpenStore usa il confinamento standard di Ubuntu Touch e non accede
al portachiavi di sistema. Formato e limiti sono descritti in [vault.md](vault.md).
Dimensione del file e orari delle modifiche restano visibili al sistema.
Una passphrase debole può essere tentata offline da chi ottiene il file cifrato.
La cifratura non protegge da un sistema compromesso mentre l'app è sbloccata.

## Autenticazione e fotocamera

Durante l'accesso, la richiesta firmata e il certificato di autenticazione sono
trasmessi al servizio CIE ufficiale. La condivisione dei dati con il servizio
richiesto prosegue nelle pagine ufficiali. Il PIN non è inviato al server e la
chiave privata non lascia la carta.

La fotocamera è usata solo durante una scansione richiesta dall'utente. I fotogrammi
sono elaborati in memoria, non salvati né inviati in rete. Il QR è validato prima
di avviare l'accesso. La fotocamera si chiude dopo riconoscimento, annullamento,
timeout o perdita del primo piano. QR, PIN, CAN, passphrase e OTP non sono scritti
nei log dell'app.

Il passaggio in background cancella i campi sensibili, nasconde i dati e blocca
l'archivio. I buffer gestiti direttamente vengono azzerati; per stringhe gestite,
rendering grafico e copie interne delle librerie non è possibile garantire la
cancellazione fisica immediata dalla memoria.

Le schermate del repository e dello store usano dati generati per la dimostrazione,
contrassegnati **DEMO**. Non contengono documenti, fotografie, certificati o codici
di accesso di persone reali.

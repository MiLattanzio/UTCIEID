# Privacy di UTCIEID

UTCIEID è un client indipendente e non è l'app ufficiale CieID. Non include
telemetria, pubblicità o un server del progetto che raccolga i dati della carta.

## Dati sul dispositivo

- Il PIN della CIE è usato per la verifica sulla carta. Se si sceglie di registrare
  la carta, viene conservato nel portachiavi di sistema tramite Secret Service.
  Il salvataggio richiede il permesso descritto in [keyring.md](keyring.md).
  Se il portachiavi non è accessibile, non viene usato un file in chiaro come alternativa.
- Il certificato di autenticazione, i dati anagrafici e la foto importata vengono
  conservati in un secondo elemento del portachiavi. Il file locale di registrazione
  contiene solo l'hash dell'identificativo servizi della carta.
- Il CAN serve solo per l'importazione della foto e dei dati ICAO. Non viene salvato.
- La chiave privata della CIE resta nel chip. Le impronte digitali non vengono lette.
- Il comando **Dimentica carta, dati e PIN** elimina i relativi elementi salvati.
  La sola disinstallazione dell'app non garantisce la cancellazione dei segreti
  custoditi dal servizio di sistema: usare prima il comando nell'app.

## Autenticazione e fotocamera

Durante l'accesso, la richiesta firmata e il certificato di autenticazione sono
trasmessi al servizio CIE ufficiale per completare l'autenticazione. La condivisione
dei dati con il servizio richiesto prosegue nelle pagine ufficiali. Il PIN non è
inviato al server e la chiave privata non lascia la carta.

La fotocamera è usata solo durante una scansione richiesta dall'utente. I fotogrammi
sono elaborati in memoria, non salvati né inviati in rete. Il risultato del QR è
validato prima di avviare l'accesso. La fotocamera si chiude dopo il riconoscimento,
all'annullamento, al timeout o quando l'app perde il primo piano. Il contenuto del
QR, il PIN, il CAN e l'OTP non sono scritti nei log dell'app.

Il passaggio in background cancella PIN, CAN e OTP dall'interfaccia. Per le stringhe
gestite non si può garantire la cancellazione fisica immediata dalla memoria.
Protezione e sblocco del portachiavi dipendono dal sistema operativo; Secret Service
non offre isolamento delle credenziali per applicazione. Dettagli in [keyring.md](keyring.md).

Le schermate pubblicate nel repository e nello store sono render dell'interfaccia
con dati generati per la dimostrazione, contrassegnati **DEMO**. Non contengono
documenti, fotografie, certificati o codici di accesso di persone reali.

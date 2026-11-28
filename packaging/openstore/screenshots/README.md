# Schermate dimostrative

PNG 1224 × 2595 generati dalla stessa interfaccia AXAML dell'app, in modalità
Avalonia Headless, con servizi sostitutivi esclusivamente in memoria.
Il badge **DEMO** identifica queste schermate. Non sono fotografie del telefono.

Il certificato è autofirmato e generato al momento con un soggetto dimostrativo;
la chiave temporanea non viene salvata. Nome, documento, codice fiscale, QR e foto
sono sintetici. La foto è una semplice icona. Nessun accesso a NFC, fotocamera,
portachiavi, browser o rete viene eseguito dal renderer.

Rigenerazione dalla radice del repository, con il fork Avalonia indicato nel README:

```sh
dotnet run --project tools/UTCIEID.Screenshots -c Release -- packaging/openstore/screenshots
```

Lo strumento non è incluso nel pacchetto Click. La sequenza mostra la lettura CIE,
il riconoscimento QR, i dati della carta, il certificato e la creazione dell'archivio
cifrato facoltativo. La versione 0.3.0 non richiede il portachiavi di sistema.

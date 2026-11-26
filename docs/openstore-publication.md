# Preparazione OpenStore — 26 novembre 2026

La scheda [UTCIEID su OpenStore](https://open-store.io/manage/utcieid.milattanzio/)
è salvata nell'account del maintainer come **bozza non pubblicata**. Il collegamento
di gestione richiede l'accesso all'account proprietario.

Sono stati caricati descrizione, categoria Utilities, parole chiave, sorgenti,
supporto, informativa privacy e note della versione 0.2.0. Le cinque schermate
provengono dall'interfaccia AXAML reale con fixture sintetiche: nessun dato della
CIE usata nelle prove. Generatore, immagini e hash sono in
[`packaging/openstore/screenshots`](../packaging/openstore/screenshots/).

## Pacchetto caricato

- `utcieid.milattanzio_0.2.0_arm64.click`, 46.666.918 byte.
- Ubuntu Touch `24.04-2.x`, architettura ARM64.
- Maintainer: `Mi Lattanzio <mi@polecola.it>`, come indicato dall'utente.
- SHA-256: `fdde5cced54412ce9026bb64502b23ec60e87d1deb973504d5a1a95bb27f30b3`.
- Controlli automatici OpenStore superati; caricamento confermato dal sito.
- Suite: 182 test passati. Pacchetto installato sul Fairphone 5, portachiavi
  sintetico verificato e AppArmor in modalità enforce.

La prima verifica automatica aveva rifiutato il formato incompleto del campo
maintainer. Il pacchetto sopra corregge quel campo e ha superato il controllo.
Le funzioni dell'app restano quelle verificate nelle [prove](verification.md).

## Revisione manuale ancora da richiedere

L'esito automatico riguarda il profilo standard con networking, NFC e fotocamera.
**Non approva né installa il permesso Secret Service** necessario a conservare PIN,
dati e foto. Il telefono di sviluppo usa la sola estensione app-specifica già
autorizzata; il Click non modifica automaticamente AppArmor su altri telefoni.

La scelta dell'utente è conservare tutte le funzioni e preparare la revisione
manuale. Non sono stati aggiunti un profilo unconfined o accesso indiscriminato
al session bus. La pubblicazione resta disattivata finché i manutentori non
indicano e approvano una modalità di distribuzione adatta per il portachiavi.

La [richiesta pronta](../packaging/openstore/manual-review-request.txt) contiene
sorgenti, istruzioni di build, impronta del pacchetto, permessi esatti e limiti di
isolamento di Secret Service. È una **bozza non inviata**: non sono stati contattati
i manutentori tramite messaggi esterni. Il passaggio successivo è sottoporla
tramite il contatto indicato nelle [regole OpenStore](https://open-store.io/submit/),
concordare i permessi, quindi verificare l'installazione senza modifiche manuali
prima di rendere pubblica la versione completa.

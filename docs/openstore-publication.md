# OpenStore — versione 0.3.0, 28 novembre 2026

Il pacchetto 0.3.0 è stato caricato nella
[scheda UTCIEID](https://open-store.io/manage/utcieid.milattanzio/) e ha superato
il controllo automatico di OpenStore. L'attivazione della pubblicazione è il
passaggio finale, dopo l'aggiornamento dei sorgenti.

## Pacchetto verificato

- `utcieid.milattanzio_0.3.0_arm64.click`, 46.682.292 byte.
- SHA-256: `22bccbbf279766ed17c3285f6996592892a93856a0ea9f5be6047cd6868e8aba`.
- Ubuntu Touch `24.04-2.x`, architettura ARM64.
- Maintainer: `Mi Lattanzio <mi@polecola.it>`.
- Profilo standard: `networking`, `nfc`, `camera`; nessun permesso del portachiavi.
- 203 test automatici superati; nove test mirati rieseguiti dopo la correzione
  del messaggio di blocco dell'archivio, tutti superati.
- Installazione su Fairphone 5 con AppArmor `enforce`; prova sintetica dell'archivio
  riuscita e accesso a Secret Service respinto dal profilo standard.
- Trasferimento verificato della carta precedente; l'utente ha confermato dati,
  foto e certificato, lettura usando il PIN salvato e lettura con PIN manuale.

Le cinque schermate provengono dall'interfaccia AXAML reale con fixture sintetiche.
Mostrano CIE, QR, dati dimostrativi, certificato e archivio cifrato. Nessun dato della
CIE usata nelle prove è incluso. Generatore, immagini e hash sono in
[`packaging/openstore/screenshots`](../packaging/openstore/screenshots/).

## Superamento della soluzione Secret Service

La bozza 0.2.0 usava il portachiavi di sistema nel dispositivo di sviluppo, tramite
un'estensione del profilo AppArmor autorizzata localmente. Il Click standard non
installava quel permesso. La richiesta di revisione è stata inviata il 26 novembre
2026 nel gruppo Telegram ufficiale OpenStore; la discussione ha evidenziato
l'assenza di isolamento dei segreti per applicazione.

La 0.3.0 sostituisce quel backend con un archivio locale cifrato a passphrase,
mantenendo il PIN manuale. Il vecchio backend è escluso dalle build ordinarie.
Non vengono richieste modifiche manuali di AppArmor agli utenti. Il trasferimento
della registrazione di sviluppo è stato effettuato con una build temporanea,
mai caricata sullo store, verificando la copia prima di rimuovere i vecchi segreti.

Non si presenta la discussione Telegram come approvazione formale dei revisori:
il risultato osservato per la 0.3.0 è il superamento dei controlli automatici sul
pacchetto confinato. La [privacy](privacy.md), il [formato dell'archivio](vault.md)
e le [verifiche](verification.md) descrivono comportamento e limiti della versione.

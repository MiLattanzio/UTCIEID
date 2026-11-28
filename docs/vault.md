# Archivio locale cifrato — formato v1

La build ordinaria usa esclusivamente `EncryptedCardVault`, all'interno della
cartella dati privata di UTCIEID. Non usa Secret Service, Secret Portal, un server
del progetto o permessi aggiuntivi. Il PIN manuale funziona anche senza archivio.

## Formato

`vault-v1.bin` contiene un header di 40 byte, il testo cifrato e un tag di 16 byte.
Tutti gli interi sono big endian.

| Offset | Dimensione | Campo |
| --- | --- | --- |
| 0 | 8 | Magic ASCII `UTCIEV01` |
| 8 | 16 | Salt casuale della derivazione |
| 24 | 12 | Nonce AES-GCM casuale, nuovo a ogni scrittura |
| 36 | 4 | Lunghezza del plaintext/ciphertext |
| 40 | variabile | JSON UTF-8 cifrato |
| finale | 16 | Tag AES-GCM |

La chiave di 32 byte è derivata dalla codifica UTF-8 esatta della passphrase
(nessuna normalizzazione o trimming) con Argon2id v1.3, 65536 KiB, tre iterazioni,
parallelismo uno. Il salt è nuovo per ogni archivio. AES-256-GCM autentica anche
l'intero header come AAD. I parametri KDF sono fissi per questa versione e non
possono essere aumentati da un file ostile. Il plaintext massimo è 2 MiB.
Implementazioni: Bouncy Castle per Argon2id, `System.Security.Cryptography.AesGcm`
per cifratura autenticata. Non vengono introdotti algoritmi crittografici propri.

Il payload contiene la registrazione (hash SHA-256 dell'identificativo servizi),
il PIN opzionale e il profilo opzionale con certificato DER, DG1/foto/SOD e date.
Nessuno di questi campi è in chiaro su disco. Si accettano solo payload coerenti
con la stessa carta; dimensioni, formato e certificato sono validati allo sblocco.
Il CAN non fa parte del payload. Non esistono una chiave di recupero o un verificatore
separato della passphrase. La nuova passphrase deve contenere almeno 12 caratteri
utili (massimo 1024); si consigliano più parole casuali.

## Persistenza e ciclo di vita

Le scritture producono solo un file temporaneo cifrato, con permessi 0600, nella
stessa cartella. Dopo flush su disco, una rename atomica sostituisce il file.
Le nuove cartelle sono 0700. Un lock esclusivo e l'impronta del pacchetto precedente
impediscono a istanze concorrenti di sovrascrivere silenziosamente dati più recenti.
Non si promette resistenza completa a perdita di alimentazione del filesystem.

Una passphrase errata o un file alterato non provocano reset o sovrascrittura.
La creazione non sovrascrive un archivio esistente. L'eliminazione richiede una
seconda azione esplicita nella UI e funziona anche con archivio bloccato.
Il PIN viene persistito solo dopo una lettura CIE riuscita e su scelta dell'utente.
Può essere rimosso separatamente dagli altri dati. Prima dell'uso del PIN salvato,
il protocollo verifica l'identificativo della carta; non vengono ripetuti tentativi
PIN automaticamente.

La chiave rimane in memoria solo durante lo sblocco. Perdita del primo piano,
chiusura o comando di blocco annullano le operazioni e cancellano la chiave, il PIN
e i buffer del profilo gestiti direttamente. Un contatore di generazione impedisce
a una derivazione in corso di riaprire l'archivio dopo il blocco. I campi password
hanno undo e suggerimenti disattivati. Le stringhe .NET e le copie interne di
librerie/rendering non offrono garanzie di cancellazione fisica immediata.

## Limiti

Il confinamento del sistema limita l'accesso fra app. La cifratura aggiunge
protezione ai dati a riposo, condizionata alla qualità della passphrase. Non
protegge da root, un kernel compromesso, cattura della tastiera o memoria del
processo sbloccato. Dimensione del file e timestamp restano pubblici al sistema.
Il formato non impedisce il ripristino di una vecchia copia valida dell'archivio
(rollback). Non viene dichiarata certificazione di sicurezza o conformità CieID.

## Migrazione della precedente build di sviluppo

`EnableLegacyMigration=true` include temporaneamente il vecchio backend, escluso
dalla build predefinita e dal Click distribuito. Serve solo al dispositivo di
sviluppo che aveva già una registrazione e accesso autorizzato a Secret Service.
La passphrase viene inserita sul telefono. Il trasferimento legge i vecchi segreti
in memoria, scrive il nuovo archivio, lo blocca e lo decifra nuovamente dal disco.
Confronta il PIN e tutti i dati del profilo prima di cancellare esclusivamente i
vecchi elementi UTCIEID. Se la verifica fallisce, non viene avviata la cancellazione.
La versione distribuita non contiene il backend né richiede questa procedura.

## Verifiche

La suite confronta la derivazione con un vettore prodotto da `libargon2`, verifica
riapertura fra istanze, passphrase errata, manomissione di ogni regione autenticata,
file troncati/sovradimensionati, permessi, nonce e salt diversi, conflitti di scrittura,
annullamento durante KDF, PIN opzionale, blocco UI e verifica prima della migrazione.
`--probe-vault` esegue sul dispositivo un round trip con soli dati sintetici in
una cartella temporanea separata e la rimuove, senza aprire l'archivio reale.

Riferimenti: [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106),
[API AesGcm .NET](https://learn.microsoft.com/dotnet/api/system.security.cryptography.aesgcm).

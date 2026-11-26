# Accesso CIE da computer con QR e OTP

Il flusso usa il QR di **livello 3**, generato dopo «Entra con lettura carta»,
«Prosegui con smartphone» e l'inserimento del numero della CIE nel browser.
Il QR di livello 2 richiede invece la certificazione del dispositivo: rimane escluso.

## Uso

Nel tab **Accedi**, scegliere **Scansiona QR** e inquadrare il codice sul computer
con la fotocamera posteriore. Il riconoscimento è automatico; l'anteprima si chiude
quando viene letto un codice. Controllare il servizio visualizzato, premere
**Genera codice OTP** e mantenere la carta ferma
dopo la vibrazione. Il PIN della carta registrata viene recuperato dal portachiavi.
Riportare le quattro cifre dell'OTP nella pagina del computer e premere «Procedi».
La conferma finale dei dati e l'accesso al servizio avvengono nel browser.

Il pulsante **Importa immagine QR** è stato rimosso. Il campo **Incolla un link**
resta disponibile per i collegamenti OpenApp e QR già decodificati. La fotocamera
non scatta né salva fotografie e non attiva il microfono. Le API native sono
documentate in [camera.md](camera.md).

Solo per diagnostica e sviluppo rimangono gli argomenti da riga di comando
`--qr-file /percorso/immagine.png`. `--probe-qr-file` decodifica e valida soltanto
l'immagine, senza rete, NFC o stampa dei parametri personali.

## Protocollo e provenienza

L'implementazione C# è indipendente; non incorpora codice o binari dell'app Android.
I dettagli necessari all'interoperabilità sono stati verificati sul pacchetto
`it.ipzs.cieid` 1.7.30 (215), ottenuto da una distribuzione pubblica e analizzato
staticamente, senza installarlo o eseguirlo. APK SHA-256:
`8c214e1d16e9e041e72d956dbc4239e2104dbe46d1fc3004cf2e1e590b7da6d8`.

`apksigner verify` ha verificato la firma; il certificato del firmatario ha SHA-256
`92d13540d450f69f792c5f3c770ae2855bfb2358b447a8de064d51d0358eb697`, corrispondente
a una delle associazioni pubblicate dal Ministero in
[assetlinks.json](https://idserver.servizicie.interno.gov.it/.well-known/assetlinks.json).
La [guida ufficiale](https://idserver.servizicie.interno.gov.it/idp/tutorial_android.jsp)
descrive il passaggio QR → lettura della carta → OTP nel browser del computer.

1. Il QR HTTPS `/idp/erroreQr.jsp` contiene `opId`, `opType=login`, `SPName`,
   `IdPName`, `userId` e il testo dell'operazione. Host e ambiente sono verificati;
   duplicati, frammenti, userinfo, porte diverse, controlli ed escape errati sono rifiutati.
2. Il contenuto **esatto** del QR, codificato UTF-8, viene firmato dalla carta
   con SHA-256 e RSA PKCS#1 v1.5. L'URL non viene ricostruito o normalizzato:
   anche gli spazi ASCII letterali di `opText`, presenti nel QR ufficiale,
   restano invariati.
3. Un POST form a `/idp/Authn/SSL/X509AuthIbrido` invia `hashJsonFirmato`
   (firma in esadecimale) e `opId`, attraverso TLS 1.2 autenticato dal certificato CIE.
   In produzione si usa l'host fisso `mtls.idserver.servizicie.interno.gov.it`:
   il 26 novembre 2026 il percorso sull'host principale ha restituito un redirect
   pubblico 307 a questo indirizzo. La negoziazione TLS del destinatario richiede
   il certificato client, mentre quella dell'host principale non lo richiede.
   Certificato server, hostname e algoritmo TLS sono stati verificati senza
   inviare dati della carta. Gli ambienti di prova non sono stati verificati online.
4. La firma TLS CertificateVerify viene eseguita dalla stessa carta, senza esportare
   la chiave privata. Bouncy Castle gestisce il protocollo TLS; catena, validità,
   hostname SAN ed EKU del server sono verificati con le API X.509 della piattaforma.
   Sono negoziabili solo ECDHE con AES-GCM. Non sono seguiti redirect.
5. Il corpo della risposta contiene un'etichetta e un OTP di quattro cifre separati
   da `:`. La risposta viene letta con limiti di dimensione e framing HTTP rigoroso;
   valori numerici di errore non vengono mostrati come codici di accesso.

Il percorso `X509AuthIbridoTLS13` del repository SDK pubblico è una costante
inutilizzata e non è stato adottato per supposizione. OpenApp conserva il suo
protocollo separato `X509TLS13First` / `X509MobileTLS13Second`.

## Gestione dei dati e verifiche

PIN, OTP, URL, certificato e firme non vengono scritti nei log. L'OTP non è salvato
e viene rimosso quando si cambia richiesta, tab o ambiente, quando si avvia una nuova
operazione e quando l'app passa in background. Non si presenta la ricezione dell'OTP
come accesso al servizio già completato.

Prima del PIN salvato viene confrontato l'identificativo servizi della carta.
Se disponibile, il profilo salvato permette anche di confrontare il documento del
QR prima di aprire il portachiavi. Il confronto è ripetuto sul certificato letto
dalla carta prima di qualunque firma o richiesta di rete.
Un PIN errato non viene ritentato e una sessione QR ammette una sola firma TLS.

I test includono immagini QR reali generate con dati sintetici, conservazione
esatta della stringa firmata, firma della richiesta e della sessione TLS sul chip
simulato, TLS interoperabile con un server .NET locale, rifiuto di server non fidati,
scaduti o con hostname diverso prima di inviare il certificato CIE, framing HTTP,
errori, leading zero dell'OTP, carta errata e stato dell'interfaccia.
La prova reale INPS è registrata separatamente in [verification.md](verification.md).

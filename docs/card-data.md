# Dati della CIE sul dispositivo

Il tab Dati appare con la registrazione e si apre al termine del salvataggio di
anagrafica e certificato. Il certificato viene conservato integralmente in DER:
la schermata mostra nome, cognome, numero documento, codice fiscale, subject,
issuer, periodo di validità, seriale e fingerprint SHA-256. Le date mostrate non
equivalgono a una verifica di revoca OCSP/CRL. La chiave privata non è esportabile.

I campi sono estratti per OID X.500, senza spezzare le stringhe DN su virgole.
La specifica CIE del 2015 inverte i numeri OID nelle due righe givenName/surname:
si usano gli OID standard 2.5.4.42 (nome) e 2.5.4.4 (cognome).

La foto appartiene all'applicazione MRTD, separata dall'applicazione IAS. L'utente
inserisce il CAN soltanto sul telefono e avvia esplicitamente la lettura. Al termine
della lettura ICAO si confronta l’hash del file servizi con la carta registrata:
la selezione IAS iniziale cambia il contesto della CIE e nasconde EF.CardAccess. Nessun PIN
viene recuperato e il trasporto di questo flusso rifiuta comunque INS 20 (VERIFY).
Sono ammessi soltanto EF.CardAccess, DG1, DG2 e SOD; DG3 e DG4 sono esclusi.

La sessione negozia un algoritmo PACE v2 DH/ECDH Generic Mapping pubblicato da
EF.CardAccess, senza fallback automatici. Le chiavi effimere usano BouncyCastle
2.7.0; secure messaging autentica MAC, status DO99 e contatore prima di usare i
dati. Sono applicati limiti a dimensioni, strutture BER e concatenazioni APDU.
Letture oltre 32 KiB usano READ BINARY B1 con oggetti 54/53.

DG1 viene interpretato come MRZ TD1 con controlli delle cifre di verifica. Le date
MRZ conservano l'anno a due cifre: non si inventa il secolo. Il volto viene estratto
dal record ISO 19794-5, usando lunghezze e numero di feature points, non cercando
una firma JPEG arbitraria nel file. Il documento deve corrispondere al numero
contenuto nel certificato IAS. Prima del salvataggio si verificano firma CMS SOD
con il certificato incorporato e hash di entrambi i data group. La fiducia nella
CA nazionale e la prova anti-clonazione ICAO sono ancora da aggiungere: la UI lo
esplicita e non dichiara il documento autenticato dalle autorità.

Il profilo e la foto originale vengono conservati in Secret Service, con il
certificato. Non sono inviati a server e non vengono creati file temporanei con
dati personali. La consultazione successiva non richiede NFC. Il CAN non è salvato.
Vedere [portachiavi](keyring.md) per attributi, limiti e autorizzazione AppArmor.

## Provenienza e fonti

- [Ministero: microprocessore CIE](https://www.cartaidentita.interno.gov.it/pa-e-imprese/specifiche-del-microprocessore-e-del-file-system/): separazione delle applicazioni, accesso CAN/MRZ, dati leggibili.
- [Ministero: specifiche chip](https://www.cartaidentita.interno.gov.it/downloads/2021/03/cie_3.0_-_specifiche_chip.pdf).
- [Ministero: impronte](https://www.cartaidentita.interno.gov.it/info-utili/conservazione-delle-impronte/): accesso riservato alle autorità abilitate.
- [JMRTD](https://jmrtd.org/): implementazione Java di ICAO, PACE/EAC e LDS, non dipendenza runtime di UTCIEID.
- [emrtd-dotnet](https://github.com/chamnan/emrtd-dotnet), commit `bdfddd0b83175065f173b197d41e59b220889627`, MIT: adattati APDU, primitive, PACE ECDH, TLV, MRZ e vettori. PACE DH (RFC 5114), trasporto nfcd, CAN, APDU estese, limiti, distruzione chiavi, validazione rigorosa SM e parser volto sono adattati per UTCIEID. Licenza in `licenses/emrtd-dotnet.txt`.
- [OpenJPEG 2.5.0](https://github.com/uclouvain/openjpeg/tree/v2.5.0), BSD-2-Clause: header per il collegamento dinamico alla libreria `libopenjp2.so.7` del dispositivo. Helper `native/portrait.c`, decodifica in memoria e dimensioni limitate a 2048×2048. Licenza inclusa.

- [SDK MRTD CIE](https://github.com/italia/cie-mrtd-dotnet-sdk): riferimento della sequenza CardAccess → PACE DH/CAN → selezione protetta LDS e lettura DG tramite SFI. Non usato come dipendenza; progetto non mantenuto.

# Mappa del porting

Sorgente: SDK Android IPZS `cieid-android-sdk`, commit
`884e8cb076e63b1f6a741a3d7a3d495d148184ab`, presente accanto a questo repository.

| Funzione Android | Implementazione C# |
| --- | --- |
| `Ias.kt`, selezioni e file | `Card/CieCard.cs`, `Card/Apdu.cs` |
| DH, DAPP e terminal certificate | `CieCard.cs`, `IasConstants.cs`, `Crypto/CardCrypto.cs` |
| Secure messaging, SSC, MAC | `Crypto/SecureMessaging.cs` |
| TLV/ASN.1 del protocollo | `Crypto/BerTlv.cs` |
| `IsoDep.transceive` | `UTCie.Linux/NfcdReader.cs` |
| Reader mode e skip NDEF | Richieste nfcd private `RequestMode(2,0)` e `RequestParams(T4_NDEF=false)` |
| Richiesta OpenApp e challenge | `Authentication/CieAuthenticationRequest.cs`, `CieIdentityProvider.cs` |
| Coordinamento lettura/firma | `CieClient.cs` |

Le costanti di terminale sono quelle pubblicate dall'SDK; non sono chiavi private
della carta. La chiave privata CIE non viene esportata.

Differenze intenzionali: status word unsigned, verifica dei MAC e della prova DAPP,
contatori per sessione, limiti sulle strutture TLV e sulle risposte, cancellazione,
timeout, nessuna ripetizione di un PIN rifiutato, confronto della carta registrata
prima del PIN, verifica locale della firma contro il certificato ricevuto.
Le richieste HTTP ammettono solo gli host HTTPS degli ambienti CIE previsti, senza
redirect automatici né cookie; usano la validazione TLS del sistema. Non vengono
riutilizzati pin TLS storici scaduti dello SDK Android. Il provider consente di
fornire pin SPKI aggiornati esplicitamente.

La prima selezione IAS può restituire `6A82`: come Android, il porting prosegue con
la selezione CIE. Per il file servizi usa P2 `04`. La corrispondenza è stata
verificata su carta reale: IAS `6A82`, CIE `9000`, file `1001` `9000`, lettura 12
byte `9000`. Nessun identificativo o PIN è incluso nei log di verifica.

Il trasporto parla con l'alias D-Bus `org.neard`, coperto dalla policy NFC standard
Ubuntu Touch, usando le interfacce `org.sailfishos.nfc.*`. Lock, reader mode e
parametri sono associati a una connessione privata, chiusa anche in caso di errore.
Il requisito attuale è nfcd con Adapter API v4 (`RequestParams`).

Il protocollo OpenApp usa due canali sicuri e due verifiche PIN riuscite, come il
flusso Android. Non sono tentativi automatici successivi a un PIN errato: al primo
errore PIN l'operazione termina.

`--probe-card-channel` verifica selezione, parametri pubblici e canale DH/DAPP
senza PIN. La funzione SDK `ProbeSecureChannelAsync` non abilita la lettura del
certificato e il trasporto della diagnostica blocca comunque ogni comando VERIFY.
La traccia contiene soltanto header APDU, status e lunghezze, senza dati della carta.

Riferimenti primari:

- [Interfacce nfcd](https://github.com/sailfishos/nfcd/tree/master/plugins/dbus_service)
- [libsecret](https://gnome.pages.gitlab.gnome.org/libsecret/)
- [HFD Ubuntu Touch](https://gitlab.com/ubports/development/core/hfd-service)
- [ICAO Doc 9303, parte 11](https://www.icao.int/sites/default/files/TRIP/Publications/Doc-9303-7th-Part11.pdf)

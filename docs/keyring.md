# PIN completo nel portachiavi

`SecretServicePinStore` usa libsecret e la collezione persistente
`/org/freedesktop/secrets/collection/login`. Il segreto ha gli attributi
`application=utcieid.milattanzio` e `card-sha256=<hash>`. Il solo hash è salvato in
`~/.local/share/utcieid.milattanzio/registered-card.json`, con permessi 0600 e
directory 0700. Non viene salvato il PIN nei file dell'app.

Dati personali, certificato DER e foto sono un secondo segreto nella stessa
collezione, con `application=utcieid.milattanzio.card-profile` e lo stesso hash.
L'attributo application distinto evita che le ricerche del PIN effettuate dalle
versioni precedenti possano trovare il profilo. Il JSON (massimo 2 MiB) passa a
libsecret in memoria; non è scritto in chiaro nei file dell'app. La cancellazione
della carta elimina entrambi i segreti. Le registrazioni precedenti, contenenti
soltanto hash e PIN, restano valide e possono importare il certificato con una
nuova lettura autorizzata dall'utente.

La registrazione è successiva alla verifica del PIN e alla lettura del certificato.
I buffer mutabili del PIN sono azzerati al termine; le stringhe del controllo UI
gestito non permettono di garantire la cancellazione fisica immediata dalla memoria.
La cifratura e lo sblocco del portachiavi sono responsabilità di Secret Service.

## Estensione AppArmor

`packaging/secret-service.apparmor.rules` permette messaggi D-Bus relativi a
Secret Service sul session bus e sul percorso `/org/freedesktop/secrets`.
libsecret usa il nome univoco del proprietario del servizio: per questo la regola
limita percorso, interfaccia e label del peer, senza vincolarsi al nome ben noto.
Non concede lettura diretta dei file del portachiavi.

**Secret Service non isola le credenziali per applicazione**: questa autorizzazione
permette tecnicamente all'app di accedere anche agli altri segreti del servizio.
Il codice UTCIEID ricerca e modifica solo gli attributi della propria carta.
L'estensione è stata esplicitamente autorizzata per questo dispositivo di sviluppo;
non è una policy standard approvata per OpenStore.

Per preparare una modifica verificabile da un profilo originale:

```sh
adb pull /var/lib/apparmor/profiles/click_utcieid.milattanzio_utcieid_0.2.0 /tmp/utcieid-original.profile
python3 scripts/prepare-keyring-profile.py /tmp/utcieid-original.profile /tmp/utcieid-keyring.profile
diff -u /tmp/utcieid-original.profile /tmp/utcieid-keyring.profile
adb push /tmp/utcieid-keyring.profile /home/phablet/utcieid-verification/utcieid-keyring.profile
```

Lo script rifiuta profili di altre applicazioni e non carica autonomamente regole.
Nel Terminale del telefono, dopo aver esaminato la differenza:

```sh
sudo apparmor_parser -r /home/phablet/utcieid-verification/utcieid-keyring.profile
```

Questo comando aggiorna solo la policy in memoria. Per conservarla al riavvio,
salvare una copia dell'originale e installare il profilo preparato nel corrispondente
file in `/var/lib/apparmor/profiles/`. Un aggiornamento Click o rigenerazione delle
policy può sovrascriverlo: verificare nuovamente dopo ogni installazione.
Per ripristinare, ricaricare e reinstallare la copia originale dello stesso profilo.

Sul telefono di sviluppo il profilo esteso è stato caricato e installato nel file
in `/var/lib/apparmor/profiles/`, mantenendo `enforce`. La copia originale è in
`/home/phablet/utcieid-verification/utcieid-original-root.profile`. La prova sintetica
è riuscita anche dopo la reinstallazione dell'app. Non sono state conservate
credenziali sudo nei file del progetto o negli script.

## Prova senza credenziali reali

Nel contesto della sessione utente del telefono:

```sh
export XDG_RUNTIME_DIR=/run/user/$(id -u)
export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus
aa-exec -p utcieid.milattanzio_utcieid_0.2.0 -- \
  /opt/click.ubuntu.com/utcieid.milattanzio/current/app/UTCIEID --probe-keyring
```

La diagnostica crea un attributo casuale, verifica PIN e certificato sintetici
come segreti distinti, riapre il profilo e verifica la cancellazione di entrambi; non legge né modifica la registrazione reale.

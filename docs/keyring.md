# Portachiavi: backend storico della versione di sviluppo 0.2.0

La versione OpenStore 0.3.0 **non usa Secret Service**. Per conservare la carta
usa l'[archivio locale cifrato](vault.md), oppure consente di inserire il PIN
manualmente. Non serve modificare AppArmor o eseguire comandi nel Terminale.

La precedente build di sviluppo salvava PIN e profilo in due elementi Secret
Service, selezionati tramite attributi dell'app e hash della carta. Il file
`registered-card.json` conteneva soltanto l'hash. L'accesso era stato autorizzato
per il solo profilo di UTCIEID sul dispositivo di sviluppo; non faceva parte del
Click standard e non è stato approvato per la distribuzione.

Secret Service non garantisce isolamento dei segreti per applicazione. La richiesta
di revisione e la successiva discussione hanno portato a sostituire questo backend,
non a concedere il relativo permesso agli utenti dello store.

I file `SecretServicePinStore.cs` e `SecretServiceCardProfile.cs` sono esclusi
normalmente dalla compilazione. L'opzione di sviluppo `EnableLegacyMigration=true`
li include esclusivamente per trasferire una registrazione preesistente sul telefono
che aveva già il permesso. Prima di rimuovere i vecchi elementi dell'app, la migrazione
verifica una nuova decifratura dell'archivio dal disco e confronta PIN e profilo.
Le istruzioni per estendere il profilo non fanno parte della procedura d'installazione.

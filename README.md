# Progetto_AD (Algoritmi Distribuiti)
Progetto Algoritmi Distribuiti - Studio di file system distribuito (FSD) realizzato in Python (RPyC).

Il progetto consiste in un file server distribuito (FSD) organizzato secondo un'architettura client-server, che sfrutta principalmente meccanismi di Remote Procedure Calls (RPC) per l'interazione tra le parti.

* Clients
    * Regular: utente base del FSD. Può gestire (upload/download/list) i propri files
    * Root: utente amministratore del FSD. Ha accesso a funzioni apposite per la manutenzione, nei limiti della privacy degli altri clients
* Servers
    * Name server: costituisce il fulcro del FSD
        * Regola le comunicazioni tra clients e file servers
        * Gestisce un database centralizzato contenente i dati di files (e relative repliche), clients, file servers nel FSD
        * Esegue periodicamente: consistency check, replicazione e garbage cleaning
    * File servers: si occupano dello storage vero e proprio dei files nel FSD
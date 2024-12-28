from BaseClient import BaseClient
import os



LOCKFILE_PATH = "./NS/rootclient.lock"



class RootClient(BaseClient):
    """Client class for root user. Root client is a singleton."""
    # TODO: rimuovere i parametri di default nel metodo __init__ (app-starter).
    # TODO: usare i parametri da riga di comando (app-starter).
    # TODO: implementare meccanismo di log-in nel metodo __main__ (app-starter).
    # TODO: implementare display comandi (app-starter).
    # TODO: implementare uscita (app-starter). Deve chiudere l'intero programma.
    # TODO: implementare visualizzazione stato di tutti i files (dfs).
    # TODO: implementare accensione/spegnimento file servers (dfs).
    # TODO: implementare creazione utenti (app-starter).
    # TODO: implementare eliminazione utenti (app-starter).
    
    # CHECKDOC: la procedura di locking è sicura?
    
    _instance   = None          # RootClient active instance.
    _lock_file  = LOCKFILE_PATH # File used to lock the root client.
    
    
    def __new__(cls, *args, **kwargs):
        """Creates a new root client."""
        
        if cls._instance is None:
            # Check if root client is already running.
            if os.path.exists(cls._lock_file):
                raise RuntimeError("Error: root client already running!")
            
            # Create a new root client.
            cls._instance = super(RootClient, cls).__new__(cls)
            
            # Lock the root client.
            with open(cls._lock_file, "w") as lock:
                lock.write("locked")
        
        return cls._instance
    
    
    def __init__(self, host="localhost", port=18861):
        """
        Initializes the root client.
        Args:
            host (str): The hostname or IP address of the name server.
            port (int): The port number of the name server.
        """
        
        pass
    
    
    def __del__(self):
        """Removes the lock file when the root client is deleted."""
        
        # Remove the lock file.
        if os.path.exists(self._lock_file):
            os.remove(self._lock_file)
    
    
    def display_commands(self):
        """Displays the available commands for the root client."""
        
        pass



if __name__ == "__main__":
    root_client = RootClient()
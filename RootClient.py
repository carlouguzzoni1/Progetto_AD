import sys
from BaseClient import BaseClient
import os



LOCKFILE_PATH = "./NS/rootclient.lock"



class RootClient(BaseClient):
    """Client class for root user. Root client is a singleton."""
    # TODO: implementare visualizzazione metadati di tutti i files attualemente
    #       nel database del name server (dfs).
    #       Formato: nome | dimensione | proprietario | checksum | server
    # TODO: implementare accensione/spegnimento logico file servers per
    #       manutenzione (dfs).
    # TODO: implementare visualizzazione dati di tutti i file servers (dfs).
    #       Formato: nome | stato | indirizzo | porta | dimensione | spazio libero
    
    # FIXME: sostituire il while True con un while not nella procedura di creazione
    #        di un root client (app-starter).
    
    # NOTE: il RootClient è pensato come un utente con privilegi speciali, che
    #       interagisce con le altre entità in caso di manutenzione del sistema.
    #       Non gli è consentito di applicare le funzioni di base al di fuori
    #       dello scopo per il quale sono state definite, per motivi di privacy.
    
    # NOTE: la procedura di locking può essere implementata utilizzando una
    #       risorsa comune, accessibile da tutti i client tramite URL. In questo
    #       modo si supera il confine dello host locale.
    
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
    
    
    def __init__(self, host, port):
        """
        Initializes the root client.
        Args:
            host (str): The hostname or IP address of the name server.
            port (int): The port number of the name server.
        """
        
        super().__init__(host, port)
    
    
    def __del__(self):
        """Removes the lock file when the root client is deleted."""
        
        # Remove the lock file.
        if os.path.exists(self._lock_file):
            os.remove(self._lock_file)
    
    
    def display_commands(self):
        """Displays the available commands for the root client."""
        
        print("""
        Welcome to sym-DFS Project Root Client.
        Commands:
        create-user         Create a new user
        delete-user         Delete a user
        exit                Exit the program
        show-commands       Show commands
        """)
    
    
    def login_as_root(self):
        """
        Authenticates the root user.
        This procedure is different from the login procedure for regular users,
        as it is mandatory and launched at the start of the program.
        """
        
        self.connect()  # Connect to the name server.
        
        while True:
            # Check if the name server has a root user.
            if not self.conn.root.exists_root_user():
                # If not, create one.
                print("No root user was found. Creating one...")
                username = input("Insert username: ")
                password = input("Insert password: ")
                
                result = self.conn.root.create_user(username, password, is_root=True)
                
                print(result["message"])
                
                # If the creation was successful, break the loop.
                if result["status"]:
                    break
            else:
                break
        
        # Login as root.
        while True:
            print("Login as root...")
            username = input("Insert username: ")
            password = input("Insert password: ")
            
            result = self.conn.root.authenticate_user(username, password, True)
            
            if result["status"]:
                self.user_is_logged     = True
                self.logged_username    = username
                
                # Check whether the root client actually has a local files directory.
                if not os.path.exists(self.files_dir):
                    os.mkdir(self.files_dir)   # Create the directory.
                
                break
            
            print(result["message"])
    
    
    def main_prompt(self):
        """Displays the main prompt for the root client."""
        
        self.display_commands() # Display the available commands.
        
        while True:
            # Get user input.
            command = input(
                "({})> ".format(self.logged_username)
            )
            
            # Execute the command.
            match command:
                case "create-user":
                    self.create_user()
                case "delete-user":
                    self.delete_user()
                case "upload":
                    self.upload_file()
                case "exit":
                    print("Exiting...")
                    # Update the user status in the name server's database.
                    self.conn.root.logout(self.logged_username)
                    # Close the connection.
                    self.conn.close()
                    break
                case "show-commands":
                    self.display_commands()
                case _:
                    print("Unknown command. Type 'show-commands' for a list of commands.")



if __name__ == "__main__":
    root_client = RootClient(sys.argv[1], int(sys.argv[2]))
    
    root_client.login_as_root() # Login as root.
    root_client.main_prompt()
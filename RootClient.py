from functools import partial
import signal
import sys
from BaseClient import BaseClient
import os
from getpass import getpass
import utils
from tabulate import tabulate
from apscheduler.schedulers.background import BackgroundScheduler
import heartbeats
import json



# Load configuration from file.
with open('root_client_config.json', 'r') as file:
    config = json.load(file)

LOCKFILE_PATH = config['lockfile_path']



class RootClient(BaseClient):
    """Client class for root user. Root client is a singleton."""
    
    # IMPROVE: si potrebbe consentire al root client di cancellare files od utenti,
    #          in modo forzato, qualora essi violassero le policy dell'amministratore.
    #          In tal caso, si dovrebbe però iscrivere il tutto in un file di log.
    
    # NOTE: il RootClient è pensato come un utente con privilegi speciali, che
    #       interagisce con le altre entità in caso di manutenzione del sistema.
    #       Non gli è consentito di applicare le funzioni di base al di fuori
    #       dello scopo per il quale sono state definite, per motivi di privacy.
    
    # NOTE: la procedura di locking può essere implementata utilizzando una
    #       risorsa comune, accessibile da tutti i client tramite URL. In questo
    #       modo si supera il confine dello host locale.
    
    _instance   = None          # RootClient active instance.
    _lock_file  = LOCKFILE_PATH # File used to lock the root client.
    
    
    ##### DUNDER METHODS #####
    
    
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
        
        # Call the destructor of the parent class.
        super().__del__()
        
        # Remove the lock file.
        if os.path.exists(self._lock_file):
            print("Removing lock file...")
            os.remove(self._lock_file)
    
    
    ##### ABSTRACT METHODS IMPLEMENTATION #####
    
    
    def display_commands(self):
        """Displays the available commands for the root client."""
        
        print("""
        Welcome to sym-DFS Project Root Client.
        Commands:
        create-user         Create a new user
        delete-user         Delete a user
        list-files          List files of the root user
        upload              Upload a file
        download            Download a file
        delete-file         Delete a file
        list-all-files      List all files in the DFS
        list-all-clients    List all clients in the DFS
        list-all-fs         List all file servers in the DFS
        exit                Exit the program
        show-commands       Show commands
        """)
    
    
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
                case "list-files":
                    self.list_files()
                case "upload":
                    self.upload()
                case "download":
                    self.download()
                case "delete-file":
                    self.delete()
                case "list-all-files":
                    self.list_all_files()
                case "list-all-clients":
                    self.list_all_clients()
                case "list-all-fs":
                    self.list_all_file_servers()
                case "exit":
                    print("Exiting...")
                    # Update the user status in the name server's database.
                    self._cleanup() # Log out before exiting.
                    # Connection is closed upon deletion, which happens on exit.
                    break
                case "show-commands":
                    self.display_commands()
                case _:
                    print("Unknown command. Type 'show-commands' for a list of commands.")
    
    
    ##### USER INTERACTION METHODS #####
    
    
    def login_as_root(self):
        """
        Authenticates the root user.
        This procedure is different from the login procedure for regular users,
        as it is mandatory and launched at the start of the program.
        """
        
        # NOTE: la procedura di creazione di un client root utilizza lo stesso metodo
        #       esposto dal file server per la creazione di un client regolare. In
        #       ogni caso, per la creazione di un utente root è richiesta una certa
        #       passphrase, definita solo lato-server e non direttamente accessibile
        #       dai client regolari.
        
        self.connect()  # Connect to the name server.
        
        # Check if the name server has a root user.
        while not self.conn.root.exists_root_user():
            # If not, create one.
            print("No root user was found. Creating one...")
            
            # Get username, password and root passphrase from the user.
            username        = input("Insert username: ")
            password        = getpass("Insert password: ")
            root_passphrase = getpass("Insert root passphrase: ")
            
            # Try to create the root user.
            result  = self.conn.root.create_user(
                username,
                password,
                True,
                root_passphrase
                )
            
            print(result["message"])
        
        # Login as root.
        while True:
            print("Login as root...")
            
            # Get username and password from the user.
            username = input("Insert username: ")
            password = getpass("Insert password: ")
            
            # Authenticate the root user.
            result = self.conn.root.authenticate_user(username, password)
            
            # Check whether the authentication was successful.
            if result["status"]:
                self.user_is_logged     = True
                self.logged_username    = username
                self.files_dir          = "./CLI/{}".format(username)
                self.token              = result["token"]
                self.scheduler          = BackgroundScheduler()
                
                # Add activity heartbeat job.
                print("Starting periodic activity heartbeat job...")
                self.scheduler.add_job(
                    heartbeats.send_activity_heartbeat,
                    args=[self.conn, self.token],
                    trigger='interval',
                    seconds=30,
                    id="activity_heartbeat"
                    )
                
                # Start the scheduler.
                self.scheduler.start()
                
                # Check whether the root client actually has a local files directory.
                if not os.path.exists(self.files_dir):
                    os.mkdir(self.files_dir)   # Create the directory.
                
                break
            
            print(result["message"])
    
    
    ##### ROOT ONLY COMMANDS #####
    
    
    def list_all_files(self):
        """Lists all files in the DFS."""
        
        result = self.conn.root.list_all_files(self.token)
        
        print(result["message"])
        
        # If the operation was successful, print the files.
        if result["status"]:
            # Convert the result to a list of dictionaries.
            headers = ["File", "Size", "Owner", "Checksum", "Is corrupted", "Uploaded at", "Server"]
            result["files"]  = [dict(zip(headers, row)) for row in result["files"]]
            
            MAX_CHECKSUM_LEN = 15
            
            result["files"] = [
                {
                    "File"          : f["File"],
                    "Size"          : f["Size"],
                    "Owner"         : f["Owner"],
                    "Checksum"      : utils.truncate(f["Checksum"], MAX_CHECKSUM_LEN),
                    "Is corrupted"  : "Y" if f["Is corrupted"] else "N",
                    "Uploaded at"   : f["Uploaded at"],
                    "Server"        : f["Server"]
                }
                for f in result["files"]
            ]
            
            print(tabulate(result["files"], headers="keys"))
    
    
    def list_all_clients(self):
        """Lists all clients in the DFS."""
        
        result = self.conn.root.list_all_clients(self.token)
        
        print(result["message"])
        
        # If the operation was successful, print the clients.
        if result["status"]:
            headers             = ["Username", "Is online"]
            result["clients"]   = [dict(zip(headers, row)) for row in result["clients"]]
            
            # Replace the boolean values with "Y" or "N".
            result["clients"]   = [
                {
                    "Username"   : c["Username"],
                    "Is online"  : "Y" if c["Is online"] else "N"
                }
                for c in result["clients"]
            ]
            
            print(tabulate(result["clients"], headers="keys"))
    
    
    def list_all_file_servers(self):
        """Lists all file servers in the DFS."""
        
        result = self.conn.root.list_all_file_servers(self.token)
        
        print(result["message"])
        
        # If the operation was successful, print the file servers.
        if result["status"]:
            headers                 = ["Name", "Is online", "Address", "Port", "Size", "Free space"]
            result["file_servers"]  = [dict(zip(headers, row)) for row in result["file_servers"]]
            
            # Replace the boolean values with "Y" or "N".
            result["file_servers"] = [
                {
                    "Name"          : f["Name"],
                    "Is online"     : "Y" if f["Is online"] else "N",
                    "Address"       : f["Address"],
                    "Port"          : f["Port"],
                    "Size"          : f["Size"],
                    "Free space"    : f["Free space"]
                }
                for f in result["file_servers"]
            ]
            
            print(tabulate(result["file_servers"], headers="keys"))



if __name__ == "__main__":
    # Create the root client.
    root_client = RootClient(sys.argv[1], int(sys.argv[2]))
    
    # Handle keyboard interrupts.
    signal.signal(signal.SIGINT, partial(utils.handle_keyboard_interrupt_client, client=root_client))
    
    root_client.login_as_root() # Mandatory login procedure for root users.
    root_client.main_prompt()   # Prompt is displayed until user manually exits.
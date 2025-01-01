from abc import ABC, abstractmethod
import os
import rpyc
import utils



class BaseClient(ABC):
    """Abstract base class for client classes."""
    # TODO: implementare visualizzazione stato dei propri files (dfs).
    # TODO: implementare download lato-client (dfs).
    # TODO: implementare cancellazione lato-client (dfs).
    
    # TODO: implementare oscuramento password utente (app-starter).
    
    # NOTE: le procedure di visualizzazione/upload/download/cancellazione di files
    #       dovrebbero essere le stesse per regular e root clients, in quanto si
    #       tratta di funzionalità di base.
    
    # NOTE: la cancellazione di un utente, per ora, avviene solo nel database del
    #       name server. Si suppone che l'utente che ne cancella un altro sia di
    #       fatto la stessa persona, ma non si fanno supposizioni sulla località
    #       di tale host. Per questo motivo, il client non si accolla l'onere di
    #       cancellare la directory locale per tale utente, che pur non essendo
    #       più registrato, potrà usufruire dei files che aveva scaricato.
    
    def __init__(self, host, port):
        """Initializes the client.
        Args:
            host (str): The hostname or IP address of the name server.
            port (int): The port number of the name server.
        """
        self.ns_host            = host
        self.ns_port            = port
        self.conn               = None
        self.user_is_logged     = False
        self.logged_username    = None
        self.files_dir          = None
    
    
    def connect(self):
        """Establishes a connection to the name server."""
        
        try:
            print("Connecting to the name server...")
            self.conn = rpyc.connect(self.ns_host, self.ns_port)
            print("Connection established.")
        
        except Exception as e:
            print(f"Error connecting to the server: {e}")
            exit(1)
    
    
    @abstractmethod
    def display_commands(self):
        """Displays the available commands for the clients."""
        
        pass
    
    
    def create_user(self):
        """
        Creates a new regular user.
        Returns:
            bool: True if the user was created successfully, False otherwise.
        """
        
        username = input("Insert username: ")
        password = input("Insert password: ")
        result = self.conn.root.create_user(username, password, False)
        print(result["message"])
    
    
    def delete_user(self):
        """Deletes a regular user."""
        
        if not self.user_is_logged:
            print("You must be logged in to delete a user.")
        else:
            username = input("Insert username: ")
            password = input("Insert password: ")
            result = self.conn.root.delete_user(username, password)
            print(result)
    
    
    @abstractmethod
    def main_prompt(self):
        """Displays the main prompt for the clients."""
        
        pass
    
    
    def upload_file(self, file_path):
        """
        Uploads a file into the DFS.
        Args:
            file_path (str): The name of the file to upload.
        """
        
        # Get file's name and size.
        file_name    = os.path.basename(file_path)
        file_size    = os.path.getsize(file_path)
        
        # Ask the name server for the file server.
        result      = self.conn.root.get_file_server(
            utils.generate_uuid(),
            file_name,
            self.logged_username,
            file_size,
            utils.calculate_checksum(file_path)
            )
        
        print(result["message"])
        
        # If a file server was not found or an error occured, exit.
        if not result["status"]:
            return
        
        # Get the file server's host and port.
        fs_host     = result["host"]
        fs_port     = result["port"]
        
        # Connect to the file server.
        fs_conn     = rpyc.connect(fs_host, fs_port)
        
        # Upload the file.
        with open(file_path, "rb") as file:
            file_data = file.read()
            upload_result = fs_conn.root.store_file(file_name, file_data)
            print(upload_result["message"])
        
        # Close the file server connection.
        fs_conn.close()
    
    
    def upload(self):
        """Uploads a file into the DFS."""
        
        if not self.user_is_logged:
            print("You must be logged in to upload a file.")
        else:
            file_path = input("Insert file path: ")
            self.upload_file(file_path)
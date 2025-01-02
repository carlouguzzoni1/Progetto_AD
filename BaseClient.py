from abc import ABC, abstractmethod
import os
import rpyc
from tabulate import tabulate
import utils
from getpass import getpass



class BaseClient(ABC):
    """Abstract base class for client classes."""
    # TODO: implementare download (dfs).
    # TODO: implementare cancellazione (dfs).
    
    # NOTE: le procedure di visualizzazione/upload/download/cancellazione di files
    #       dovrebbero essere le stesse per regular e root clients, in quanto si
    #       tratta di funzionalità di base.
    
    # NOTE: la cancellazione di un utente, per ora, avviene solo nel database del
    #       name server. Si suppone che l'utente che ne cancella un altro sia di
    #       fatto la stessa persona, ma non si fanno supposizioni sulla località
    #       di tale host. Per questo motivo, il client non si accolla l'onere di
    #       cancellare la directory locale per tale utente, che pur non essendo
    #       più registrato, potrà ugualmente usufruire dei files che aveva scaricato.
    
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
        self.token              = None
    
    
    def __del__(self):
        """Tries to update the client's status in the name server's database
        (to False) and close connection upon deletion.
        """
        
        print("Shutting down client...")
        
        # Update the client's status in the name server's database.
        if self.user_is_logged:
            try:
                self.conn.root.update_client_status(self.logged_username, False, self.token)
            
            except Exception as e:
                print(f"Error updating client status: {e}")
            
            finally:
                # Close the connection.
                self.conn.close()
    
    
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
        password = getpass("Insert password: ")
        result = self.conn.root.create_user(username, password)
        print(result["message"])
    
    
    def delete_user(self):
        """Deletes a regular user."""
        
        if not self.user_is_logged:
            print("You must be logged in to delete a user.")
        else:
            username = input("Insert username: ")
            password = getpass("Insert password: ")
            result = self.conn.root.delete_user(username, password)
            print(result)
    
    
    @abstractmethod
    def main_prompt(self):
        """Displays the main prompt for the clients."""
        
        pass
    
    
    def list_files(self):
        """Lists the user's files in the DFS."""
        
        if not self.user_is_logged:
            print("You must be logged in to list files.")
        else:
            result = self.conn.root.get_user_files(self.token)
            
            print(result["message"])
            
            # If the operation was successful, print the result.
            if result["status"]:
                # Convert the result to a list of dictionaries.
                headers = ["File", "Owner", "Size", "Checksum", "Primary Server"]
                result["files"]  = [dict(zip(headers, row)) for row in result["files"]]
                
                MAX_CHECKSUM_LEN = 15
                
                result["files"] = [
                    {
                        "File"          : f["File"],
                        "Owner"         : f["Owner"],
                        "Size"          : f["Size"],
                        "Checksum"      : utils.truncate(f["Checksum"], MAX_CHECKSUM_LEN),
                        "Primary Server": f["Primary Server"]
                    }
                    for f in result["files"]
                ]
                
                print(tabulate(result["files"], headers="keys"))
    
    
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
        result      = self.conn.root.get_file_server_upload(
            utils.generate_uuid(),
            file_name,
            self.token,
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
        """User interface for uploading a file."""
        
        if not self.user_is_logged:
            print("You must be logged in to upload a file.")
        else:
            file_path = input("Insert file path: ")
            self.upload_file(file_path)
    
    
    def download_file(self, file_name):
        """
        Downloads a file from the DFS.
        Args:
            file_name (str): The name of the file to download.
        """
        
        pass
    
    
    def download(self):
        """User interface for downloading a file."""
        
        if not self.user_is_logged:
            print("You must be logged in to download a file.")
        else:
            file_name = input("Insert file name: ")
            self.download_file(file_name)
from abc import ABC, abstractmethod
import os
import rpyc
from tabulate import tabulate
import utils
from getpass import getpass
from apscheduler.schedulers.background import BackgroundScheduler



# IMPROVE: da spostare su variabili d'ambiente/file di configurazione.
CLIENT_ROOT_DIR = "./CLI"



class BaseClient(ABC):
    """Abstract base class for client classes."""
    
    def __init__(self, host, port):
        """
        Initializes the client.
        Args:
            host (str): The hostname or IP address of the name server.
            port (int): The port number of the name server.
        """
        
        # The root directory of the client.
        self.client_root_dir    = CLIENT_ROOT_DIR
        self.ns_host            = host  # Host for the name server.
        self.ns_port            = port  # Port for the name server.
        self.conn               = None  # Connection to the name server.
        self.user_is_logged     = False # Whether the user is logged in.
        self.logged_username    = None  # The username of the logged in user.
        self.files_dir          = None  # The directory of the logged in user.
        self.token              = None  # The JWT token of the logged in user.
        self.scheduler          = None  # The job scheduler.
    
    
    def __del__(self):
        """Closes the connection to the name server upon deletion."""
        
        print("Shutting down client...")
        
        # Close the connection.
        print("Closing the connection to the name server...")
        self.conn.close()
    
    
    def _cleanup(self):
        """Cleans up the client's state upon logout or keyboard interrupt."""
        
        # Update the user status in the name server's database.
        print("Logging out...")
        
        try:
            result = self.conn.root.logout(self.token)
            print(result)
        
        except Exception as e:
            print(f"Error logging out: {e}")
        
        # Reset the client's state.
        print("Resetting the client's state...")
        
        self.user_is_logged     = False
        self.logged_username    = None
        self.files_dir          = None
        self.token              = None
        
        # Stop the scheduler.
        print("Shutting down the job scheduler...")
        
        self.scheduler.remove_all_jobs()
        self.scheduler.shutdown()
        self.scheduler          = None
    
    
    def connect(self):
        """Establishes a connection to the name server."""
        
        print("Connecting to the name server...")
        
        try:
            self.conn = rpyc.connect(self.ns_host, self.ns_port)
            print("Connection established.")
        
        except Exception as e:
            print(f"Error connecting to the server: {e}")
            exit(1)
    
    
    ##### ABSTRACT METHODS #####
    
    
    @abstractmethod
    def display_commands(self):
        """Displays the available commands for the clients."""
        
        pass
    
    
    @abstractmethod
    def main_prompt(self):
        """Displays the main prompt for the clients."""
        
        pass
    
    
    ##### BASE CLIENT FUNCTIONALITIES #####
    
    
    # NOTE: le procedure di creazione/eliminazione di utenti sono le stesse per
    #       regular e root clients, in quanto si tratta di funzionalità di base.
    
    
    def create_user(self):
        """
        Creates a new regular user.
        Returns:
            bool: True if the user was created successfully, False otherwise.
        """
        
        username    = input("Insert username: ")
        password    = getpass("Insert password: ")
        result      = self.conn.root.create_user(username, password)
        print(result["message"])
    
    
    def delete_user(self):
        """Deletes a regular user."""
        
        # NOTE: la cancellazione di un utente, per ora, avviene solo nel database del
        #       name server. Si suppone che l'utente che ne cancella un altro sia di
        #       fatto la stessa persona, ma non si fanno supposizioni sull'ubicazione
        #       di tale host. Per questo motivo, il client non si accolla l'onere di
        #       cancellare la directory locale per tale utente, che pur non essendo
        #       più registrato, potrà ugualmente usufruire dei files che aveva in
        #       precedenza scaricato.
        
        if not self.user_is_logged:
            print("You must be logged in to delete a user.")
        else:
            username    = input("Insert username: ")
            password    = getpass("Insert password: ")
            result      = self.conn.root.delete_user(username, password)
            print(result)
    
    
    # NOTE: le procedure di visualizzazione/upload/download/cancellazione di files
    #       sono le stesse per regular e root clients, in quanto si tratta di
    #       funzionalità di base.
    
    
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
                headers         = ["File", "Size", "Is corrupted", "Uploaded at", "Primary Server"]
                result["files"] = [dict(zip(headers, row)) for row in result["files"]]
                                
                result["files"] = [
                    {
                        "File"          : f["File"],
                        "Size"          : f["Size"],
                        "Is corrupted"  : f["Is corrupted"],
                        "Uploaded at"   : f["Uploaded at"],
                        "Primary Server": f["Primary Server"]
                    }
                    for f in result["files"]
                ]
                
                print(tabulate(result["files"], headers="keys"))
    
    
    def upload_file(self, client_path, server_path):
        """
        Uploads a file into the DFS.
        Args:
            client_path (str): The absolute path of the file to upload.
            server_path (str): The directory where the file will be stored.
        """
        
        # Calculate the checksum of the file.
        checksum    = utils.calculate_checksum(client_path)
        
        # Get the file's name and size.
        file_name   = os.path.basename(client_path)
        file_size   = os.path.getsize(client_path)
        
        # Concatenate the file path with the file name to get the absolute path
        # server-side.
        server_path = os.path.join(server_path, file_name)
        
        # Ask the name server for the file server.
        result      = self.conn.root.get_file_server_upload(
            self.token,
            server_path,
            file_size,
            checksum
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
        with open(client_path, "rb") as file:
            file_data       = file.read()
            upload_result   = fs_conn.root.store_file(
                server_path,
                file_data,
                self.token
                )
            print(upload_result["message"])
        
        # Close the file server connection.
        fs_conn.close()
    
    
    def upload(self):
        """User interface for uploading a file."""
        
        if not self.user_is_logged:
            print("You must be logged in to upload a file.")
        else:
            file_name   = input("Insert absolute file path: ")
            server_path = input("Insert the directory where the file will be stored: ")
            
            # Check if the file exists.
            if not os.path.exists(file_name):
                print(f"File {file_name} not found.")
                
                return
            
            self.upload_file(file_name, server_path)
    
    
    def download_file(self, server_path):
        """
        Downloads a file from the DFS.
        Args:
            server_path (str): The absolute path of the file to download on the DFS.
        """
        
        # Ask the name server for a file server to download the file.
        result      = self.conn.root.get_file_server_download(self.token, server_path)
        
        print(result["message"])
        
        # If a file server was not found or an error occured, exit.
        if not result["status"]:
            return
        
        # Get the file server's host and port.
        fs_host     = result["host"]
        fs_port     = result["port"]
        
        # Connect to the file server.
        fs_conn     = rpyc.connect(fs_host, fs_port)
        
        # Get the file name.
        file_name   = os.path.basename(server_path)
        
        # Create all the directories to store the file.
        dir         = self.files_dir
        
        for directory in server_path.split("/")[1:-1]:
            dir     = os.path.join(dir, directory)
            
            if not os.path.exists(dir):
                os.mkdir(dir)
        
        # Concatenate the file path with the file name to get the absolute path
        # client-side.
        client_path = os.path.join(dir, file_name)
        
        # Download the file.
        with open(client_path, "wb") as file:
            result = fs_conn.root.send_file(server_path, self.token)
            
            print(result["message"])
            file.write(result["file_data"])
        
        # Close the file server connection.
        fs_conn.close()
    
    
    def download(self):
        """User interface for downloading a file."""
        
        if not self.user_is_logged:
            print("You must be logged in to download a file.")
        else:
            server_abs_path = input("Insert the absolute path of the file to download: ")
            
            self.download_file(server_abs_path)
    
    
    def delete_file(self, server_path):
        """
        Deletes a file from the DFS.
        Args:
            server_path (str): The absolute path of the file to delete.
        """
        
        result = self.conn.root.delete_file(server_path, self.token)
        
        print(result)
    
    
    def delete(self):
        """User interface for deleting a file."""
        
        if not self.user_is_logged:
            print("You must be logged in to delete a file.")
        else:
            server_abs_path = input("Insert the absolute path of the file to delete: ")
            
            self.delete_file(server_abs_path)
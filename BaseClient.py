from abc import ABC, abstractmethod
import rpyc



class BaseClient(ABC):
    """Abstract base class for client classes."""
    # NOTE: le procedure di upload/download/display status di files dovrebbero
    #       essere le stesse per regular e root clients.
    # TODO: implementare visualizzazione stato dei propri files (dfs).
    # TODO: implementare upload (dfs).
    # TODO: implementare download (dfs).
    
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
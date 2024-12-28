from abc import ABC, abstractmethod
import rpyc



class BaseClient(ABC):
    """Abstract base class for client classes."""
    
    def __init__(self, host="localhost", port=18861):
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
        """Displays the available commands for the client."""
        pass
import sys
import rpyc



class FileServer(rpyc.Service):
    """
    Implements the file server, which is a storage node in the sym-DFS
    architecture.
    """
    
    def __init__(self, ns_host, ns_port):
        self.ns_host    = ns_host
        self.ns_port    = ns_port
        self.conn       = None
        self.host       = None
        self.port       = None
        self.files_dir  = None
    
    
    def connect(self):
        """Establishes a connection to the name server."""
        
        try:
            print("Connecting to the name server...")
            self.conn = rpyc.connect(self.ns_host, self.ns_port)
            print("Connection established.")
        except Exception as e:
            print(f"Error connecting to the server: {e}")
            exit(1)
    
    
    def display_commands(self):
        """Displays the available commands for the file server."""
        
        print("""
            Welcome to sym-DFS Project File Server.
            Commands:
            register        Register a new file server
            login           Log in as an existing file server
            exit            Exit
        """)
    
    
    def register(self):
        """Registers a new file server."""
        
        print("Registering new file server...")
        name        = input("Insert server's name: ")
        password    = input("Insert password: ")
        host        = input("Insert server's host: ")
        port        = input("Insert server's port: ")
        
        result      = self.conn.root.create_file_server(name, password, host, port)
        
        print(result["message"])
    
    
    def login(self):
        """Logs in as an existing file server."""
        
        print("Logging in...")
        name        = input("Insert server's name: ")
        password    = input("Insert password: ")
        
        result      = self.conn.root.authenticate_file_server(name, password)
        
        if result["status"]:
            self.host       = result["host"]
            self.port       = result["port"]
            self.files_dir  = result["directory"]
        
        print(result["message"])
        
        return result["status"]
    
    
    def main_prompt(self):
        """Main prompt for the file server."""
        
        self.connect()              # Connect to the name server.
        self.display_commands()     # Display the available commands.
        
        while True:
            # Get user input.
            command = input("(fs prompt)> ")
            
            # Execute the command.
            match command:
                case "register":
                    self.register()
                case "login":
                    if self.login():
                        break                    
                case "exit":
                    print("Exiting...")
                    # Close the connection.
                    self.conn.close()
                    exit(0)
                case _:
                    print("Unknown command.")



if __name__ == "__main__":
    from rpyc.utils.server import ThreadedServer
    
    file_server = FileServer(sys.argv[1], int(sys.argv[2])) # Create the file server.
    # Prompt is displayed until a login is successful.
    file_server.main_prompt()
    
    server = ThreadedServer(file_server, port=file_server.port)
    
    print("Starting file server...")
    server.start()
import os
import sys
import rpyc



class FileServer(rpyc.Service):
    """
    Implements the file server, which is a storage node in the sym-DFS
    architecture.
    """
    # TODO: implementare oscuramento password file server (app-starter).
    
    # TODO: implementare meccanismo di spegnimento per interruzioni forzate.
    
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
        size        = input("Insert server's size (in bytes): ")
        
        if int(size) < 0:
            print("Invalid size. Must be a positive integer.")
            return
        
        result      = self.conn.root.create_file_server(name, password, host, port, size)
        
        print(result)
    
    
    def login(self):
        """Logs in as an existing file server."""
        
        print("Logging in...")
        name        = input("Insert server's name: ")
        password    = input("Insert password: ")
        
        result      = self.conn.root.authenticate_file_server(name, password)
        
        if result["status"]:
            self.host       = result["host"]
            self.port       = result["port"]
            self.files_dir  = "./FS/{}".format(name)
            
            # Check whether the file server actually has a local storage directory associated.
            if not os.path.exists(self.files_dir):
                os.mkdir(self.files_dir)   # Create the directory.
        
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
    
    
    def exposed_store_file(self, file_name, file_data):
        """
        Stores a file on the file server.
        Args:
            filename (str): The name of the file.
            data (bytes):   The content of the file.
        Returns:
            bool:           True if the file is stored successfully, False otherwise.
        """
        
        # Create the new file path.
        file_path = os.path.join(self.files_dir, file_name)
        
        # Try to store the file.
        try:
            with open(file_path, "wb") as file:
                file.write(file_data)
            
            return {"status": True, "message": "File stored successfully."}
        
        except Exception as e:
            print(f"Error storing file '{file_name}': {e}")
            
            return {"status": False, "message": "Error storing file."}



if __name__ == "__main__":
    from rpyc.utils.server import ThreadedServer
    
    file_server = FileServer(sys.argv[1], int(sys.argv[2])) # Create the file server.
    # Prompt is displayed until a login is successful.
    file_server.main_prompt()
    
    server = ThreadedServer(file_server, port=file_server.port)
    
    print("Starting file server...")
    server.start()
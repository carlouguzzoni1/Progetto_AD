import os
import sys
import rpyc
from getpass import getpass
import jwt



class FileServer(rpyc.Service):
    """
    Implements the file server, which is a storage node in the sym-DFS
    architecture.
    """
    
    def __init__(self, ns_host, ns_port):
        self.ns_host        = ns_host
        self.ns_port        = ns_port
        self.conn           = None
        self.host           = None
        self.port           = None
        self.files_dir      = None
        self.name           = None
        self.token          = None
        self._public_key    = None
    
    
    def __del__(self):
        """
        Tries to update the file server's status in the name server's database
        (to False) and close connection upon deletion.
        """
        
        print("Shutting down file server...")
        
        # Update the file server's status in the name server's database.
        try:
            self.conn.root.update_file_server_status(self.name, False, self.token)
        
        except Exception as e:
            print(f"Error updating file server status: {e}")
        
        finally:
            # Close the connection.
            self.conn.close()
    
    
    def _get_token_payload(self, token):
        """
        Gets the payload of a JWT token.
        Args:
            token (str):  The JWT token.
        Returns:
            dict:         The payload of the token.
        """
        
        try:
            payload = jwt.decode(token, self._public_key, algorithms=["RS384"])
        
        except jwt.InvalidTokenError as e:
            print("Error decoding JWT token:", e)
            
            return None
        
        return payload
    
    
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
        password    = getpass("Insert password: ")
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
        password    = getpass("Insert password: ")
        
        result      = self.conn.root.authenticate_file_server(name, password)
        
        if result["status"]:
            self.host       = result["host"]
            self.port       = result["port"]
            self.files_dir  = "./FS/{}".format(name)
            self.name       = name
            self.token      = result["token"]
            self._public_key = result["public_key"]
            
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
            command = input("({})> ".format(self.name) if self.name else "(fs prompt)> ")
            
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
    
    
    def exposed_store_file(self, file_path, file_data, token):
        """
        Stores a file on the file server.
        Args:
            file_path (str):        The path of the file to store.
            file_data (bytes):      The data of the file to store.
            token (str):            The token of the client.
        Returns:
            dict:                   A dictionary containing the status of the operation.
        """
        
        # Get the username from the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            return {"status": False, "message": "Error storing file. Corrupted token."}
        else:
            username = payload["username"]
        
        # Check whether there is already a base directory for the username.
        user_basedir = os.path.join(self.files_dir, username)
        
        if not os.path.exists(user_basedir):
            os.mkdir(user_basedir)
        
        # Split the file path into directories.
        directories = file_path.split("/")
        dir         = user_basedir
        
        # Get the file name.
        file_name = os.path.basename(file_path)
        
        # Create the directories (if needed).
        for directory in directories[:-1]:
            dir = os.path.join(dir, directory)
            
            if not os.path.exists(dir):
                os.mkdir(dir)
        
        # Create the new file path.
        file_path = os.path.join(dir, file_name)
        
        # Try to store the file.
        try:
            with open(file_path, "wb") as file:
                file.write(file_data)
            
            return {"status": True, "message": "File stored successfully."}
        
        except Exception as e:
            print(f"Error storing file '{file_name}': {e}")
            
            return {"status": False, "message": "Error storing file."}
    
    
    def exposed_send_file(self, file_path, token):
        """
        Sends a file to the client.
        Args:
            file_path (str):    The path of the file to send.
            token (str):        The token of the client.
        Returns:
            dict:               A dictionary containing the file data.
        """
        
        # Get the username from the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            return {"status": False, "message": "Error sending file. Corrupted token."}
        else:
            username = payload["username"]
        
        # Check whether the username applying the request is the same as the owner.
        # username must be the same as the higher directory in the file path.
        if os.path.dirname(file_path).split("/")[0] != username:
            return {
                "status": False,
                "message": "User does not own the file. Access denied."
                }
        
        # Combine the root directory with the file path to get the absolute file path.
        file_path = os.path.join(self.files_dir, file_path)
        
        # Check if the absolute path contains dangerous characters (..).
        if ".." in file_path:
            return {"status": False, "message": "Invalid file path Access denied."}
        
        # Check if the file exists.
        if not os.path.exists(file_path):
            return {"status": False, "message": "File not found."}
        
        # Read the file data.
        with open(file_path, "rb") as file:
            file_data = file.read()
            
        return {
            "status": True,
            "file_data": file_data,
            "message": "File received successfully."
            }



if __name__ == "__main__":
    from rpyc.utils.server import ThreadedServer
    
    file_server = FileServer(sys.argv[1], int(sys.argv[2])) # Create the file server.
    # Prompt is displayed until a login is successful.
    file_server.main_prompt()
    
    server = ThreadedServer(file_server, port=file_server.port)
    
    print("Starting file server...")
    server.start()
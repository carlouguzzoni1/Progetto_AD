import os
import sys
import rpyc
from getpass import getpass
import jwt
import heartbeats
from apscheduler.schedulers.background import BackgroundScheduler



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
        
        # Stop the scheduler.
        print("Shutting down the job scheduler...")
        if self.scheduler:
            self.scheduler.remove_all_jobs()
            self.scheduler.shutdown()
            self.scheduler = None
        
        # Update the file server's status in the name server's database.
        print("Updating client status...")
        
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
            self.host           = result["host"]
            self.port           = result["port"]
            self.files_dir      = "./FS/{}".format(name)
            self.name           = name
            self.token          = result["token"]
            self._public_key    = result["public_key"]
            self.scheduler      = BackgroundScheduler()
            
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
        
        # Verify the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            return {"status": False, "message": "Error storing file. Corrupted token."}
        
        # Get the base directory in the file server storage.
        dir         = self.files_dir
        
        # Split the file path into directories.
        directories = file_path.split("/")
        
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
    
    
    def exposed_send_file_replicas(self, file_path, file_servers):
        """
        Sends a file to a list of file servers.
        Args:
            file_path (str):        The path of the file to send.
            file_servers (list):    A list of file servers to send the file to.
        """
        
        # Iterate through the file servers and send the file.
        for server in file_servers:
            # Connect to the file server. server is a list of tuples.
            fs_conn         = rpyc.connect(server[1], server[2])
            
            # Add the base directory to the file path.
            abs_file_path   = os.path.join(self.files_dir, file_path)
            
            # Send the replica to the file server.
            with open(abs_file_path, "rb") as file:
                file_data   = file.read()
                result      = fs_conn.root.store_file(file_path, file_data, self.token)
                
                print(result["message"])
    
    
    def exposed_garbage_collection(self, db_files):
        """
        Deletes all the files in the file server that are not in the list, in
        order to synchronize the file server with the database.
        Args:
            db_files (list):    A list of the files according to the database.
        """
        
        # Transform the list of tuples to a list of strings.
        db_files = [file[0] for file in db_files]
        
        # Get all the files in the local storage.
        local_files = []
        
        for root, _, files in os.walk(self.files_dir):
            for file in files:
                local_files.append(os.path.join(root, file))
        
        # Add the storage directory to every file received, so to get its
        # absolute path in the local storage.
        db_files = [os.path.join(self.files_dir, file) for file in db_files]
        
        # Get the files to delete as the difference between the two lists.
        files_to_delete = list(set(local_files) - set(db_files))
        
        # Delete all the files that are not in the list from the local storage.
        for file in files_to_delete:
            try:
                os.remove(file)
                print(f"Deleted {file}")
                
            except Exception as e:
                print("Error deleting file")
        
        # Delete all empty directories in the local storage.
        for root, dirs, _ in os.walk(self.files_dir):
            for dir in dirs:
                
                # Get the relative path of the directory.
                dir_path = os.path.join(root, dir)
                
                if not os.listdir(dir_path):
                    # Try to remove the empty directory
                    try:
                        # os.rmdir works only if the directory is empty anyways.
                        os.rmdir(dir_path)
                        print(f"Deleted empty directory: {dir_path}")
                    
                    except Exception as e:
                        print("Error deleting empty directory")



if __name__ == "__main__":
    from rpyc.utils.server import ThreadedServer
    
    file_server = FileServer(sys.argv[1], int(sys.argv[2])) # Create the file server.
    # Prompt is displayed until a login is successful.
    file_server.main_prompt()
    
    server = ThreadedServer(file_server, port=file_server.port)
    
    print("Starting file server...")
    server.start()
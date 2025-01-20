from functools import partial
import os
import signal
import sys
import rpyc
from rpyc.utils.server import ThreadedServer
from getpass import getpass
import jwt
import heartbeats
from apscheduler.schedulers.background import BackgroundScheduler
import utils



class FileServer(rpyc.Service):
    """
    Implements the file server, which is a storage node in the sym-DFS
    architecture.
    """
    
    # NOTE: per ora è permessa solo la cancellazione di utenti. Il progetto
    #       è pensato per simulare un piccolo DFS, quindi non dovrebbe
    #       accadere spesso che un file server venga rimosso.
    #       Nel caso, implementare la cancellazione dei file servers è
    #       un task relativamente semplice. Esempio:
    #           1. aggiungere il campo is_deleted a tutti i files
    #           2. assegnare ad un altro primary file server (tra quelli
    #              che ospitano una replica) tutti i files che avevano
    #              come primary file server quello da cancellare
    #           3. marcare tutti i files a cui non si è trovata una nuova
    #              sistemazione come "deleted"
    #           4. cancellare le entry relative al file server e le repliche
    #              in suo possesso
    #           5. facoltativo: cancellare le directory di storage locali
    
    # TODO: si dovrebbe implementare un meccanismo per rendere le RPC definite
    #       appositamente per l'interazione name server/file server inutilizzabili
    #       al client.
    
    def __init__(self, ns_host, ns_port):
        """
        Initializes the file server.
        Args:
            ns_host (str):  The hostname or IP address of the name server.
            ns_port (int):  The port number of the name server.
        """
        
        self.ns_host        = ns_host   # Host for the name server.
        self.ns_port        = ns_port   # Port for the name server.
        self.conn           = None      # Connection to the name server.
        self.host           = None      # Host for the file server.
        self.port           = None      # Port for the file server.
        self.files_dir      = None      # The storage directory of the file server.
        self.name           = None      # The name of the file server.
        self.token          = None      # The JWT token of the file server.
        self._public_key    = None      # Public key for JWT tokens.
        self._server        = None      # The ThreadedServer instance for the file server.
    
    
    def __del__(self):
        """
        Tries to update the file server's status in the name server's database
        (to False) and close connection upon deletion.
        """
        
        print("Shutting down file server...")
        
        # Close the connection.
        print("Closing the connection to the name server...")
        self.conn.close()
    
    
    ##### PRIVATE METHODS #####
    
    
    def _cleanup(self):
        """Cleans up the file server's state upon logout or keyboard interrupt."""
        
        # NOTE: ampliare il cleanup con i reset di stato nel caso in cui si
        #       voglia implementare un sistema di login/logout per i file servers.
        
        # Update the file server's status in the name server's database.
        print("Logging out...")
        
        try:
            result = self.conn.root.logout_file_server(self.token)
            print(result)
        
        except Exception as e:
            print(f"Error logging out: {e}")
        
        # Stop the scheduler.
        print("Shutting down the job scheduler...")
        
        if self.scheduler:
            self.scheduler.remove_all_jobs()
            self.scheduler.shutdown()
    
    
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
    
    
    ##### USER INTERACTION METHODS #####
    
    
    def display_commands(self):
        """Displays the available commands for the file server."""
        
        print("""
            Welcome to sym-DFS Project File Server.
            Commands:
            register        Register a new file server
            login           Log in as an existing file server
            exit            Exit
        """)
    
    
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
    
    
    ##### CLIENTS RPCs #####
    
    
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
        
        # DEBUG
        print(f"Storing file '{file_path}'...")
        
        # Verify the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            return {"status": False, "message": "Error storing file. Corrupted token."}
        
        # Get the base directory in the file server storage.
        dir         = self.files_dir
        
        # Split the file path into directories.
        directories = file_path.split("/")
        
        # Get the file name.
        file_name   = os.path.basename(file_path)
        
        # Create the directories (if needed).
        for directory in directories[:-1]:
            dir = os.path.join(dir, directory)
            
            if not os.path.exists(dir):
                os.mkdir(dir)
        
        # Create the new file path.
        file_path   = os.path.join(dir, file_name)
        
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
        
        # DEBUG
        print(f"Sending file '{file_path}'...")
        
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
    
    
    ##### NAME SERVER RPCs #####
    
    
    def exposed_send_file_replicas(self, file_path, file_servers):
        """
        Sends a file to a list of file servers.
        Args:
            file_path (str):        The path of the file to send.
            file_servers (list):    A list of file servers to send the file to.
        """
        
        # DEBUG
        print(f"Received request to send replicas for file '{file_path}'.")
        
        # Iterate through the file servers and send the file.
        for server in file_servers:
            # DEBUG
            print(f"Sending replica to file server {server[0]}...")
            
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
        
        print(f"[{utils.current_timestamp()}] Running garbage collection...")
        
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
                
                # DEBUG
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
                        
                        # DEBUG
                        print(f"Deleted empty directory: {dir_path}")
                    
                    except Exception as e:
                        print("Error deleting empty directory")
    
    
    def exposed_consistency_check(self, files):
        """
        Checks the consistency of the files stored in the file server.
        Args:
            files (list):    A list of the files and their checksums according
            to the database.
        """
        
        # TEST: cancellazione file nella directory di primary e non primary fs.
        
        print(f"[{utils.current_timestamp()}] Running consistency check...")
        
        # For each file, get its checksum.
        for file in files:
            # Add the storage directory to the file path, so to get its
            # absolute path in the local storage.
            local_path = os.path.join(self.files_dir, file[0])
            
            # If the file exists, calculate its checksum.
            if os.path.exists(local_path):
                checksum = utils.calculate_checksum(local_path)
                
                # If the file is corrupted, demand database update to the name server.
                if file[1] != checksum:
                    # DEBUG
                    print(f"File {file[0]} is corrupted.")
                    
                    result = self.conn.root.handle_file_inconsistency(self.token, file[0])
                    print(result)
            
            # If the file does not exist, demand database update to the name server.
            else:
                # DEBUG
                print(f"File {file[0]} does not exist.")
                
                result = self.conn.root.handle_file_inconsistency(self.token, file[0])
                print(result)



if __name__ == "__main__":
    
    # Create the file server.
    file_server = FileServer(sys.argv[1], int(sys.argv[2]))
    
    # Handle keyboard interrupts.
    signal.signal(
        signal.SIGINT,
        partial(utils.handle_keyboard_interrupt_file_server, file_server=file_server)
        )
    
    # Prompt is displayed until a login is successful.
    file_server.main_prompt()
    
    # Start the file server.
    server = ThreadedServer(
        file_server,
        hostname=file_server.host,
        port=file_server.port
        )
    
    # Associate the ThreadedServer to the file server.
    file_server._server = server
    
    print("Starting file server...")
    server.start()
import os
import random
import sqlite3
import rpyc
from bcrypt import hashpw, gensalt, checkpw
import jwt
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization



LOCKFILE_PATH   = "./NS/nameserver.lock"
DB_PATH         = "./NS/NS.db"
SERVER_PORT     = 18861

# NOTE: i parametri di sicurezza vengono impostati come variabili globali per
#       semplicità. Nonappena possibile si migrerà verso l'uso di variabili
#       d'ambiente o file di configurazione protetti.
PRIVATE_KEY      = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
PUBLIC_KEY      = PRIVATE_KEY.public_key()
PRIVATE_KEY     = PRIVATE_KEY.private_bytes(    # Private key for JWT tokens.
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()   # No password for simplicity.
            ).decode("utf-8")
print(PRIVATE_KEY)
PUBLIC_KEY      = PUBLIC_KEY.public_bytes(      # Public key for JWT tokens.
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")
print(PUBLIC_KEY)
ROOT_PASSPHRASE = "sym-DFS-project"



class NameServerService(rpyc.Service):
    """
    Represents the name server, which is the central node in the sym-DFS architecture.
    Name server is a singleton.
    """
    
    # NOTE: sebbene sia stata implementata la disconnessione logica sul database
    #       in ogni client e file server, è possibile che il name server venga
    #       disconnesso in modo improvviso prima che le altre componenti possano
    #       a loro volta disconnettersi in modo sicuro. In casi come questo,
    #       clients e file servers permangono nel database come connessi.
    #       La soluzione migliore potrebbe essere quella di implementare un
    #       meccanismo di heart-beat, che controlli periodicamente lo stato delle
    #       connessioni attive e vada ad aggiornare il database.
    #       Se il name server viene disconnesso in modo improvviso poco importa,
    #       perché lo stato del database non avrà più importanza a quel punto.
    # TODO: sostituire i metodi update_client_status e update_file_server_status
    #       con logout_client (già esistente) ed una controparte per file servers,
    #       oppure rimpiazzare in toto con il meccanismo di heart-beat descritto
    #       sopra.
    
    # NOTE: sqlite3 è di default in modalità "serialized", ciò significa che si
    #       possono eseguire più thread in simultanea senza restrizioni.
    #       https://docs.python.org/3/library/sqlite3.html#sqlite3.threadsafety
    #       Il progetto si può estendere per supportare accesso concorrente al DB.
    
    _instance           = None              # NameServerService active instance.
    _lock_file          = LOCKFILE_PATH     # File used to lock the file server.
    
    
    def __new__(cls, *args, **kwargs):
        """Creates a new name server."""
        
        if cls._instance is None:
            # Check if name server is already running.
            if os.path.exists(cls._lock_file):
                raise RuntimeError("Error: name server already running!")
            
            # Create a new name server.
            cls._instance = super(NameServerService, cls).__new__(cls)
            
            # Lock the name server.
            with open(cls._lock_file, "w") as lock:
                lock.write("locked")
        
        return cls._instance
    
    
    def __init__(self, host="localhost", port=SERVER_PORT):
        self.db_path            = DB_PATH
        self.server_port        = port
        self._private_key       = PRIVATE_KEY       # Private key for JWT tokens.
        self._public_key        = PUBLIC_KEY        # Public key for JWT tokens.
        self._root_passphrase   = ROOT_PASSPHRASE   # Root passphrase for creating root users.
        
        self._setup_database()
    
    
    def __del__(self):
        """Removes the lock file when the name server is deleted."""
        
        print("Shutting down name server...")
        
        # Remove the lock file.
        if os.path.exists(self._lock_file):
            os.remove(self._lock_file)
    
    
    def _setup_database(self):
        """
        Creates the nameserver's database (if it doesn't exist) and initializes it.
        """
        
        if os.path.exists(DB_PATH):
            print("Database already exists.")
        else:
            # Create the database.
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create users table.
            try:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        password_hash TEXT NOT NULL,
                        is_root BOOLEAN NOT NULL DEFAULT 0,
                        is_online BOOLEAN NOT NULL DEFAULT 0
                    );
                """)
            except sqlite3.OperationalError as e:
                print("Error creating users table:", e)
            
            # Create file servers table.
            try:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS file_servers (
                        name TEXT PRIMARY KEY,
                        password_hash TEXT NOT NULL,
                        address TEXT NOT NULL,
                        port INTEGER NOT NULL,
                        is_online BOOLEAN NOT NULL DEFAULT 0,
                        size INTEGER NOT NULL,
                        free_space INTEGER NOT NULL,
                        last_heartbeat TIMESTAMP,
                        UNIQUE (address, port)
                    );
                """)
            except sqlite3.OperationalError as e:
                print("Error creating file servers table:", e)
            
            # Create files table.
            try:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS files (
                        file_path TEXT PRIMARY KEY,
                        file_name TEXT NOT NULL,
                        owner TEXT NOT NULL,
                        size INTEGER NOT NULL,
                        checksum TEXT NOT NULL,
                        primary_server TEXT NOT NULL,
                        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (primary_server) REFERENCES file_servers (name),
                        FOREIGN KEY (owner) REFERENCES users (username)
                    );
                """)
            except sqlite3.OperationalError as e:
                print("Error creating files table:", e)
            
            # Create replicas table.
            try:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS replicas (
                        file_path TEXT NOT NULL,
                        server TEXT NOT NULL,
                        FOREIGN KEY (file_path) REFERENCES files (file_path),
                        FOREIGN KEY (server) REFERENCES file_servers (name),
                        PRIMARY KEY (file_path, server)
                    );
                """)
            except sqlite3.OperationalError as e:
                print("Error creating replicas table:", e)
            
            conn.commit()            
            conn.close()
            
            print("Database created.")
    
    
    def _generate_token(self, user_id, role):
        """
        Generates a JWT token for the client.
        Args:
            user_id (str):  The username of the user.
            role (str):     The role of the user.
        Returns:
            str:            The generated JWT token.
        """
        
        payload = {
            "username": user_id,
            "role":     role
        }
        token = jwt.encode(payload, self._private_key, algorithm="RS384")
        
        return token
    
    
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
    
    
    def exposed_create_user(self, username, password, is_root=False, root_passphrase=None):
        """
        Creates a new user.
        Args:   
            username (str):         The username of the new user.
            password (str):         The password of the new user.
            is_root (bool):         Whether the new user is a root user.
            root_passphrase (str):  The passphrase of the root user.
        Returns:
            dict:                   A dictionary containing the result of the operation
                                    and a message.
        """
        
        conn            = sqlite3.connect(self.db_path)
        cursor          = conn.cursor()
        hashed_password = hashpw(password.encode('utf-8'), gensalt())
        
        # Check if someone unauthorized is trying to create a root user.
        if is_root and root_passphrase != ROOT_PASSPHRASE:
            return {
                "status": False,
                "message": "Invalid root passphrase. Unauthorized action."
            }
        
        # Create the user.
        try:
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, is_root, is_online)
                VALUES (?, ?, ?, ?)
                """,
                (username, hashed_password, is_root, False)
            )
            conn.commit()
            
            return {
            "status": True,
            "message": f"User '{username}' created successfully."
            }
        
        except sqlite3.IntegrityError as e:
            print(f"Error creating user '{username}':", e)
            
            return {
                "status": False,
                "message": f"Error: user '{username}' already exists."
                }
        
        finally:
            conn.close()
    
    
    def exposed_create_file_server(self, name, password, host, port, size):
        """
        Creates a new file server.
        Args:
            name (str):     The name of the new file server.
            password (str): The password of the new file server.
            host (str):     The host of the new file server.
            port (int):     The port of the new file server.
            size (int):     The size of the new file server.
        Returns:
            str:            A message indicating the result of the operation.
        """
        
        conn            = sqlite3.connect(self.db_path)
        cursor          = conn.cursor()
        hashed_password = hashpw(password.encode('utf-8'), gensalt())
        
        # Verify conflicts with the name server.
        if host == "localhost" or host == "127.0.0.1":
            if port == self.server_port:
                return f"Error: File server port {port} conflicts with Name Server port."
        
        # Create the file server.
        try:
            cursor.execute("""
                INSERT INTO file_servers (name, password_hash, address, port, size, free_space)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (name, hashed_password, host, port, size, size)
                )
            conn.commit()
            
            return f"File server '{name}' created successfully."
        
        except sqlite3.IntegrityError as e:
            print(f"Error creating file server '{name}':", e)
            
            return f"Error: file server '{name}' already exists."
        
        finally:
            conn.close()
    
    
    def exposed_authenticate_user(self, username, password):
        """
        Authenticates a user.
        Args:
            username (str): The username of the user.
            password (str): The password of the user.
        Returns:
            dict:           A dictionary containing the result of the operation.
        """
        
        conn    = sqlite3.connect(self.db_path)
        cursor  = conn.cursor()
        
        # Get user online status, hashed password and root status.
        try:
            cursor.execute("""
                SELECT is_online, password_hash, is_root
                FROM users
                WHERE username = ?
                """,
                (username,)
                )
            result  = cursor.fetchone()
        
        except sqlite3.OperationalError as e:
            conn.close()
            print(f"Error selecting record for user '{username}':", e)
            
            return {
                "status": False,
                "message": f"Error authenticating user '{username}'."
                }
        
        # Check whether login can't be done.
        
        # Check user existence. User must exist.
        if result is None:
            conn.close()
            
            return {
                "status": False,
                "message": f"Error: user '{username}' not found."
                }
        
        # Check user online status. User must not be online.
        if result[0]:
            conn.close()
            
            return {
                "status": False,
                "message": f"Error: user '{username}' already logged in."
                }
        
        # Check user password validity. Password must be correct.
        password_match = checkpw(password.encode('utf-8'), result[1])
        
        if not password_match:
            conn.close()
            
            return {
                "status": False,
                "message": f"Error: wrong password for user '{username}'."
                }
        
        # If login can be done (checks passed successfully).
        
        # Check user root status. Create a token depending on the root status.
        if result[2]:
            token = self._generate_token(username, "root")
        else:
            token = self._generate_token(username, "regular")
        
        # Try to update user online status.
        try:
            cursor.execute("""
                UPDATE users
                SET is_online = 1
                WHERE username = ?
                """,
                (username,)
                )
            conn.commit()
            
            return {
                "status": True,
                "message": f"User '{username}' authenticated successfully.",
                "token": token
                }
        
        except sqlite3.OperationalError as e:
            print(f"Error updating record for user '{username}':", e)
            
            return {
                "status": False,
                "message": f"Error authenticating user '{username}'."
                }
        
        finally:
            conn.close()
    
    
    def exposed_authenticate_file_server(self, name, password):
        """
        Authenticates a file server.
        Args:
            name (str):     The name of the file server.
            password (str): The password of the file server.
        Returns:
            dict:           A dictionary containing the result of the operation.
        """
        
        conn    = sqlite3.connect(self.db_path)
        cursor  = conn.cursor()
        
        # Get file server online status, hashed password, address and port.
        try:
            cursor.execute("""
                SELECT is_online, password_hash, address, port
                FROM file_servers
                WHERE name = ?
                """,
                (name,)
                )
            result  = cursor.fetchone()
        
        except sqlite3.OperationalError as e:
            print(f"Error selecting record for file server '{name}':", e)
            conn.close()
            
            return {
                "status": False,
                "message": f"Error connecting to the database."
                }
        
        # Check whether login can't be done.
        
        # Check file server existence. File server must exist.
        if result is None:
            conn.close()
            
            return {
                "status": False,
                "message": f"Error: file server '{name}' not found."
                }
        
        # Check file server online status. File server must not be online.
        if result[0]:
            conn.close()
            
            return {
                "status": False,
                "message": f"Error: file server '{name}' already logged in."
                }
        
        # Check file server password validity. Password must be correct.
        password_match = checkpw(password.encode('utf-8'), result[1])
        
        if not password_match:
            conn.close()
            
            return {
                "status": False,
                "message": f"Error: wrong password for file server '{name}'."
                }
        
        # If login can be done (checks passed successfully).
        
        # Generate a token.
        token = self._generate_token(name, "file_server")
        
        # Try to update file server online status.
        try:
            cursor.execute("""
                UPDATE file_servers
                SET is_online = 1
                WHERE name = ?
                """,
                (name,)
                )
            conn.commit()
            
            return {
                "status": True,
                "message": f"File server '{name}' authenticated successfully.",
                "host": result[2],
                "port": result[3],
                "token": token,
                "public_key": self._public_key
                }
        
        except sqlite3.OperationalError as e:
            print(f"Error updating record for file server '{name}':", e)
            
            return {
                "status": False,
                "message": f"Error connecting to the database."
                }
        
        finally:
            conn.close()
    
    
    def exposed_delete_user(self, username, password):
        """
        Deletes a user.
        Args:
            username (str): The username of the user.
            password (str): The password of the user.
        Returns:
            str:            A message indicating the result of the operation.
        """
        # TEST cancellazione utente con files.
        
        conn            = sqlite3.connect(self.db_path)
        cursor          = conn.cursor()
        
        # Get user root status, hashed password and online status.
        try:            
            cursor.execute("""
                SELECT is_root, password_hash, is_online
                FROM users
                WHERE username = ?
                """,
                (username,)
                )
            result = cursor.fetchone()
        
        except sqlite3.OperationalError as e:
            print("Error selecting record for user:", e)
            conn.close()
            
            return f"Error deleting user."
        
        # Check user existence. User must exist.
        if result is None:
            conn.close()
            
            return f"Error: user '{username}' not found."
        
        # Check user root status. User must not be root.
        if result[0]:
            conn.close()
            
            return f"Error: you don't have the needed permissions to delete user '{username}'."
        
        # Check user online status. User must not be online.
        if result[2]:
            conn.close()
            
            return f"Error: user '{username}' is currently logged in."
        
        # Check user password validity. Password must be correct.
        password_match = checkpw(password.encode('utf-8'), result[1])
        
        if not password_match:
            conn.close()
            
            return f"Error: wrong password for user '{username}'."
        
        # Delete the user and his/her files and replicas.
        try:
            cursor.execute(
                """
                DELETE FROM users WHERE username = ?
                """,
                (username,)
                )
            conn.commit()
            
            cursor.execute(
                """
                DELETE FROM files WHERE owner = ?
                """,
                (username,)
                )
            conn.commit()
            
            cursor.execute(
                """
                DELETE FROM replicas WHERE owner = ?
                """,
                (username,)
                )
            conn.commit()
            
            return f"User '{username}' deleted successfully."
        
        except sqlite3.OperationalError as e:
            print("Error while deleting user:", e)
            conn.close()
            
            return f"Error deleting user {username}."
        
        finally:
            conn.close()
    
    
    def exposed_exists_root_user(self):
        """
        Checks whether there is a root user in the name server's database.
        Returns:
            bool: True if there is a root user, False otherwise.
        """
        
        conn        = sqlite3.connect(self.db_path)
        cursor      = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT is_root
                FROM users
                WHERE is_root = 1
                """)
            result  = cursor.fetchone()
            
            conn.close()
            
            return result is not None
        
        except sqlite3.OperationalError as e:
            print("Error selecting record for user:", e)
            conn.close()
            
            return False
    
    
    def exposed_logout(self, token):
        """
        Logs out a user.
        Args:
            token (str):    The JWT token of the user.
        Returns:
            str:            A message indicating the result of the operation.
        """
        
        conn            = sqlite3.connect(self.db_path)
        cursor          = conn.cursor()
        
        # Get the username from the token.
        payload         = self._get_token_payload(token)
        
        if payload is None:
            conn.close()
            
            return f"Error logging out. Corrupted token."
        else:
            username    = payload["username"]
        
        # Update the user's online status.
        try:
            cursor.execute("""
                UPDATE users
                SET is_online = 0
                WHERE username = ?
                """,
                (username,)
                )
            conn.commit()
            conn.close()
            
            return f"User '{username}' logged out successfully."
        
        except sqlite3.OperationalError as e:
            print("Error updating record for user:", e)
            conn.close()
            
            return f"Error logging out user '{username}'."
    
    
    def exposed_get_user_files(self, token):
        """
        Gets the files owned by a user.
        Args:
            token (str):    The JWT token of the user.
        Returns:
            list:           A list of dictionaries containing the file information.
        """
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get the username from the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            conn.close()
            
            return {
                "status": False,
                "message": "Error getting user files. Corrupted token."
                }
        else:
            username = payload["username"]
        
        # Get the files owned by the user.
        try:
            cursor.execute("""
                SELECT file_path, size, checksum, uploaded_at, primary_server
                FROM files
                WHERE owner = ?
                """,
                (username,)
                )
            result = cursor.fetchall()
            
            # Check whether the user has any files.
            if not result:
                return {
                    "status": False,
                    "message": f"User '{username}' has no files."
                    }
            else:
                return {
                    "status": True,
                    "message": f"Files for user '{username}' retrieved successfully.",
                    "files": result
                    }
        
        except sqlite3.OperationalError as e:
            print(f"Error selecting record for user:", e)
            
            return {
                "status": False,
                "message": f"Error retrieving files for user '{username}'."
                }
        
        finally:
            conn.close()
    
    
    def exposed_get_file_server_upload(self, file_path, token, file_size, checksum):
        """
        Gets the best file server to store a file according to K-least loaded
        policy.
        Args:
            file_path (str):    The absolute path of the file.
            token (str):        The JWT token of the user.
            file_size (int):    The size of the file.
            checksum (str):     The checksum of the file.
        Returns:
            dict:               A dictionary containing the file server information.
        """
        
        # Get the file's name.
        file_name = os.path.basename(file_path)
        
        K = 3
        
        # Get the K least loaded file servers.
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT name, address, port, free_space
                FROM file_servers
                WHERE is_online = 1
                ORDER BY free_space DESC
                LIMIT ?
                """,
                (K,)
                )
            result = cursor.fetchall()
        
        except sqlite3.OperationalError as e:
            print("Error selecting record for file server:", e)
            
            return {
                "status": False,
                "message": f"Error getting best file server for file '{file_name}'."
                }
        
        finally:
            conn.close()
        
        # Check if there is any file server available.
        if len(result) == 0:
            return {
                "status": False,
                "message": f"No file server available for file '{file_name}'."
            }
        
        # Select the best file server randomly.
        random.shuffle(result)
        best_file_server = None
        
        # Iterate through the file servers to find the first one with enough free space.
        for file_server in result:
            if int(file_server[3]) >= file_size:
                best_file_server = file_server
                break
        
        # If no file server has enough free space, return an error message.
        if best_file_server is None:
            return {
                "status": False,
                "message": f"No file server has enough free space for file '{file_name}'."
            }
        
        # Update the file server's free space.
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                UPDATE file_servers
                SET free_space = ?
                WHERE name = ?
                """,
                (int(best_file_server[3]) - file_size, best_file_server[0])
                )
            conn.commit()
        
        except sqlite3.OperationalError as e:
            print(f"Error updating record for file server {best_file_server[0]}:", e)
        
        finally:
            conn.close()
        
        # Get the username from the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            return {
                "status": False,
                "message": f"Error getting user files. Corrupted token."
                }
        else:
            username = payload["username"]
        
        # Add the username as base directory for the file.
        file_path = os.path.join(username, file_path)
        
        # Create new entry into the files table.
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO files (file_path, file_name, owner, size, checksum, primary_server)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (file_path, file_name, username, file_size, checksum, best_file_server[0])
                )
            conn.commit()
        
        except sqlite3.OperationalError as e:
            print(f"Error inserting record for file:", e)
        
        finally:
            conn.close()
        
        # Create a new entry into the replicas table.
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO replicas (file_path, server)
                VALUES (?, ?)
                """,
                (file_path, best_file_server[0])
                )
            conn.commit()
        
        except sqlite3.OperationalError as e:
            print(f"Error inserting record for replica of file:", e)
        
        finally:
            conn.close()
        
        return {
            "status": True,
            "message": f"Best file server found.",
            "host": best_file_server[1],
            "port": best_file_server[2]
            }
    
    
    def exposed_update_file_server_status(self, name, status, token):
        """
        Turns off a file server.
        Args:
            name (str):     The name of the file server.
            status (bool):  The new status of the file server.
            token (str):    The token of the requestor.
        Returns:
            str:            A message indicating the result of the operation.
        """
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get username and role from the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            return f"Error turning off file server '{name}'. Corrupted token."
        else:
            username = payload["username"]
            role     = payload["role"]
        
        # Check whether the requestor has the necessary privileges.
        if role != "file_server" or username != name:
            return f"""
                Error turning off file server '{name}'.
                Requestor does not have the necessary privileges.
                """
        
        # Check whether the file server is already turned off.
        
        # Turn off the file server.
        try:
            cursor.execute("""
                UPDATE file_servers
                SET is_online = ?
                WHERE name = ?
                """,
                (int(status), name)
                )
            conn.commit()
            
            return f"File server '{name}' turned off successfully."
        
        except sqlite3.OperationalError as e:
            print(f"Error updating record for file server:", e)
            
            return f"Error turning off file server '{name}'."
        
        finally:
            conn.close()
    
    
    def exposed_update_client_status(self, username, status, token):
        """
        Updates the status of a client.
        Args:
            username (str): The username of the client.
            status (bool):  The new status of the client.
        Returns:
            str:            A message indicating the result of the operation.
        """
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get username and role from the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            return f"Error updating client '{username}'. Corrupted token."
        else:
            token_username = payload["username"]
        
        # Check whether the requestor has the necessary privileges.
        if token_username != username:
            return f"""
                Error updating client '{username}'.
                Requestor does not have the necessary privileges.
                """
        
        # Update the client's status.
        try:
            cursor.execute("""
                UPDATE users
                SET is_online = ?
                WHERE username = ?  
                """,
                (int(status), username)
                )
            conn.commit()
            
            return f"Client '{username}' updated successfully."
        
        except sqlite3.OperationalError as e:
            print(f"Error updating record for client:", e)
            
            return f"Error updating client '{username}'."
        
        finally:
            conn.close()


if __name__ == "__main__":
    from rpyc.utils.server import ThreadedServer
    
    server = ThreadedServer(NameServerService, port=SERVER_PORT)
    
    print("Welcome to sym-DFS Project Server.")
    print("Starting name server...")
    server.start()

import rpyc.lib
from rpyc.utils.server import ThreadedServer
import os
import random
import sqlite3
import rpyc
from bcrypt import hashpw, gensalt, checkpw
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import threading
from apscheduler.schedulers.background import BackgroundScheduler



# IMPROVE: la porta del server ed i percorsi di database e lockfile dovrebbero
#       essere spostati su variabili d'ambiente o files di configurazione.

LOCKFILE_PATH   = "./NS/nameserver.lock"
DB_PATH         = "./NS/NS.db"
SERVER_HOST     = "localhost"
SERVER_PORT     = 18861

# IMPROVE: i parametri di sicurezza vengono impostati come variabili globali per
#       semplicità. Anche per questi ci si dovrebbe servire di un altro tipo
#       di meccanismo.

# NOTE: per le interazioni potenzialmente critiche tra client e server, ci si
#       serve di un sistema di verifica tramite token JWT. Il token è generato
#       per entrambi clients e file servers. La chiave segreta è RSA a 2048 bit.
#       La chiave pubblica è distribuita solo ai file servers, ed utilizzata da
#       name server e file servers per autenticare i token.

# Generate private and public keys.
PRIVATE_KEY     = rsa.generate_private_key(
    public_exponent         = 65537,
    key_size                = 2048
)
PUBLIC_KEY      = PRIVATE_KEY.public_key()

# Convert keys to strings.
PRIVATE_KEY     = PRIVATE_KEY.private_bytes(
    encoding                = serialization.Encoding.PEM,
    format                  = serialization.PrivateFormat.PKCS8,
    # No password for simplicity.
    encryption_algorithm    = serialization.NoEncryption()           
    ).decode("utf-8")
PUBLIC_KEY      = PUBLIC_KEY.public_bytes(
    encoding                = serialization.Encoding.PEM,
    format                  = serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

# NOTE: la passphrase è il meccanismo che consente ai root users di potersi
#       registrare come tali. La verifica della passphrase avviene lato-file
#       server e ha lo scopo di non permettere in nessun caso ad altri clients
#       di accedere alla registrazione di root users.

# Root passphrase for creating root users.
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
    # IMPROVE: la soluzione migliore potrebbe essere quella di implementare un
    #       meccanismo di heart-beat, che controlli periodicamente lo stato delle
    #       connessioni attive e vada ad aggiornare il database.
    #       Se il name server viene disconnesso in modo improvviso poco importa,
    #       perché lo stato del database non avrà più importanza a quel punto.
    
    # NOTE: sqlite3 è di default in modalità "serialized", ciò significa che si
    #       possono eseguire più thread in simultanea senza restrizioni.
    #       https://docs.python.org/3/library/sqlite3.html#sqlite3.threadsafety
    #       Il progetto si può estendere per supportare accesso concorrente al DB.
    
    _instance           = None              # NameServerService active instance.
    _lock_file          = LOCKFILE_PATH     # File used to lock the file server.
    
    
    def __new__(cls, *args, **kwargs):
        """Creates a new name server."""
        
        # NOTE: questo meccanismo di lock serve a garantire l'effettività del
        #       design pattern Singleton, dunque l'esistenza di un solo name
        #       server per l'intero sistema.
        
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
    
    
    def __init__(self, host=SERVER_HOST, port=SERVER_PORT):
        # FIXME: cambiare tutti i controlli rispetto lo host del name server da
        #       "localhost"/"127.0.0.1" a self.host.
        self.server_host        = host              # Host for the name server.
        self.server_port        = port              # Port for the name server.
        self.db_path            = DB_PATH           # Local path to the database.
        self._private_key       = PRIVATE_KEY       # Private key for JWT tokens.
        self._public_key        = PUBLIC_KEY        # Public key for JWT tokens.
        self._root_passphrase   = ROOT_PASSPHRASE   # Root passphrase for creating root users.
        
        self._setup_database()
    
    
    def __del__(self):
        """Removes the lock file when the name server is deleted."""
        
        print("Shutting down name server...")
        
        # Remove the lock file.
        if os.path.exists(self._lock_file):
            print("Removing lock file...")
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
            if int(port) == self.server_port:
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
        
        # Verify that the first directory has the same name as the username.
        if file_path.split("/")[0] != username:
            return {
                "status": False,
                "message": f"Error sending file. Base directory does not match username."
                }
        
        # Verify that the file path does not contain any '..'.
        if ".." in file_path:
            return {
                "status": False,
                "message": f"Error sending file. Invalid file path."
                }
        
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
    
    
    def exposed_get_file_server_download(self, file_path, token):
        """
        Gets the primary server for a file, or in case it is offline, the first
        file server available to download the file.
        Args:
            file_path (str):    The path of the file in the DFS.
            token (str):        The token of the requestor.
        Returns:
            dict:               A dictionary containing the file server information.
        """
        
        # Get the username from the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            return {
                "status": False,
                "message": f"Error getting file server. Corrupted token."
                }
        else:
            username = payload["username"]
        
        # Get host and port of the primary server for the file.
        conn    = sqlite3.connect(self.db_path)
        cursor  = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT primary_server, address, port
                FROM files
                JOIN file_servers ON files.primary_server = file_servers.name
                WHERE file_path = ?
                AND owner = ?
                """,
                (file_path, username)
                )
            result = cursor.fetchone()
        
        except sqlite3.OperationalError as e:
            print(f"Error selecting record for file:", e)
            
            return {
                "status": False,
                "message": f"Error getting file server for file '{file_path}'."
                }
        
        finally:
            conn.close()
        
        # Check whether there is a primary server for the file.
        if result is None:
            # If not, look for another file server to download the file.
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            try:
                cursor.execute("""
                    SELECT server, address, port
                    FROM files
                    JOIN replicas ON files.file_path = replicas.file_path
                    JOIN file_servers ON replicas.server = file_servers.name
                    WHERE file_path = ?
                    """,
                    (file_path,)
                    )
                result = cursor.fetchone()
            
            except sqlite3.OperationalError as e:
                print(f"Error selecting record for replica of file:", e)
                
                return {
                    "status": False,
                    "message": f"Error getting file server for file '{file_path}'."
                    }
            
            finally:
                conn.close()
            
            # If no file server is available, return an error message.
            if result is None:
                return {
                    "status": False,
                    "message": f"Could'nt find an onlinefile server for file '{file_path}'."
                    }
        
        return {
            "status": True,
            "message": f"File server found.",
            "host": result[1],
            "port": result[2]
            }
    
    
    def exposed_delete_file(self, file_path, token):
        """
        Deletes a file from the DFS.
        Args:
            file_path (str):    The path of the file in the DFS.
            token (str):        The token of the requestor.
        """
        
        # Get the username from the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            return f"Error deleting file. Corrupted token."
        else:
            username = payload["username"]
        
        # Delete the file from the replicas table.
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                DELETE FROM replicas
                WHERE file_path = ?
                AND ? = (
                    SELECT owner
                    FROM files
                    WHERE file_path = ?
                )
                """,
                (file_path, username, file_path)
                )
            conn.commit()
        
        except sqlite3.OperationalError as e:
            print(f"Error deleting record for replica of file:", e)
            
            return f"Error deleting replicas of file '{file_path}'."
        
        finally:
            conn.close()
        
        # Delete the file from the files table.
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                DELETE FROM files
                WHERE file_path = ?
                AND owner = ?
                """,
                (file_path, username)
                )
            conn.commit()
        
        except sqlite3.OperationalError as e:
            print(f"Error deleting record for file:", e)
            
            return f"Error deleting file '{file_path}'."
        
        finally:
            conn.close()
        
        return f"File '{file_path}' deleted."
    
    
    def exposed_list_all_files(self, token):
        """
        Lists all files in the DFS.
        Args:
            token (str):    The token of the requestor.
        Returns:
            list:           A list of dictionaries containing the file information.
        """
        
        # Get the client's role from the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            return {
                "status": False,
                "message": "Error listing files. Corrupted token."
                }
        else:
            role = payload["role"]
        
        # Check the role of the client.
        if role != "root":
            return {
                "status": False,
                "message": "Error listing files. Only admin can list files."
                }
        
        # Get the metadata of all files in the DFS.
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT f.file_path, f.size, f.owner, f.checksum, f.uploaded_at, r.server
                FROM files AS f
                JOIN replicas AS r ON f.file_path = r.file_path
                """)
            result = cursor.fetchall()
        
        except sqlite3.OperationalError as e:
            print(f"Error selecting records for files:", e)
            
            return {
                "status:": False,
                "message": "Error listing files."
                }
        
        finally:
            conn.close()
        
        return {
            "status": True,
            "message": "Listing files",
            "files": result
            }
    
    
    def exposed_list_all_clients(self, token):
        """
        Lists all clients in the DFS.
        Args:
            token (str):    The token of the requestor.
        Returns:
            list:           A list of dictionaries containing the client information.
        """
        
        # Get the client's role from the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            return {
                "status": False,
                "message": "Error listing clients. Corrupted token."
                }
        else:
            role = payload["role"]
        
        # Check the role of the client.
        if role != "root":
            return {
                "status": False,
                "message": "Error listing clients. Only admin can list clients."
                }
        
        # Get the metadata of all clients in the DFS.
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT username, is_online
                FROM users
                """)
            result = cursor.fetchall()
        
        except sqlite3.OperationalError as e:
            print(f"Error selecting records for clients:", e)
            
            return {
                "status:": False,
                "message": "Error listing clients."
                }
        
        finally:
            conn.close()
        
        return {
            "status": True,
            "message": "Listing clients",
            "clients": result
            }
    
    
    def exposed_list_all_file_servers(self, token):
        """
        Lists all file servers in the DFS.
        Args:
            token (str):    The token of the requestor.
        Returns:
            list:           A list of dictionaries containing the file server information.
        """
        
        # Get the client's role from the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            return {
                "status": False,
                "message": "Error listing file servers. Corrupted token."
                }
        else:
            role = payload["role"]
        
        # Check the role of the client.
        if role != "root":
            return {
                "status": False,
                "message": "Error listing file servers. Only admin can list file servers."
                }
        
        # Get the metadata of all file servers in the DFS.
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT name, is_online, address, port, size, free_space
                FROM file_servers
                """)
            result = cursor.fetchall()
        
        except sqlite3.OperationalError as e:
            print(f"Error selecting records for file servers:", e)
            
            return {
                "status:": False,
                "message": "Error listing file servers."
                }
        
        finally:
            conn.close()
        
        return {
            "status": True,
            "message": "Listing file servers",
            "file_servers": result
            }
    
    
    # TODO: sostituire i metodi update_client_status e update_file_server_status
    #       con logout_client (già esistente) ed una controparte per file servers,
    #       oppure rimpiazzare in toto con il meccanismo di heart-beat descritto
    #       sopra.
    
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


def periodic_replication_job(K):
    """
    Periodically replicates the files in the DFS up to K times.
    Args:
        K (int):    The number of times to replicate the files.
    """
    
    conn    = sqlite3.connect(DB_PATH)
    cursor  = conn.cursor()
    
    # Select the files that need to be replicated and their primary server.
    try:
        cursor.execute("""
            SELECT 
                f.file_path,
                COUNT(r.server) as active_replicas
            FROM files AS f
            JOIN replicas AS r ON f.file_path = r.file_path
            JOIN file_servers AS fs ON r.server = fs.name
            WHERE fs.is_online = 1
            GROUP BY f.file_path
            HAVING active_replicas < ?
            """,
            (K, )
            )
        files_to_replicate = cursor.fetchall()
        
        print("RICERCA FILES DA REPLICARE")
        if files_to_replicate is not None:
            print("DEBUG. FILES DA REPLICARE:", files_to_replicate)
    
    except sqlite3.OperationalError as e:
        print(f"Error selecting records for replication:", e)
    
    finally:
        conn.close()
    
    # For every file that needs to be replicated.
    for file_path, active_replicas in files_to_replicate:
        conn    = sqlite3.connect(DB_PATH)
        cursor  = conn.cursor()
        
        # Select address and port of the primary server.
        try:
            cursor.execute("""
                SELECT address, port
                FROM file_servers AS fs
                JOIN files AS f ON fs.name = f.primary_server
                WHERE f.file_path = ?
                """,
                (file_path, )
                )
            primary_server = cursor.fetchone()
        
        except sqlite3.OperationalError as e:
            print(f"Error selecting record for file '{file_path}':", e)
        
        finally:
            conn.close()
        
        # If the primary server is offline, continue.
        print(f"DEBUG. PRIMARY SERVER: {primary_server}")
        if not primary_server:
            print(f"File server is offline. Skipping file '{file_path}'.")
            
            continue
        
        conn    = sqlite3.connect(DB_PATH)
        cursor  = conn.cursor()
        
        # Select address and port of the file servers which don't have the file,
        # up to (K - active_replicas).
        try:
            cursor.execute("""
                SELECT fs.name, fs.address, fs.port
                FROM file_servers AS fs
                WHERE fs.name NOT IN (
                    SELECT server
                    FROM replicas
                    JOIN files ON replicas.file_path = files.file_path
                    WHERE files.file_path = ?
                    )
                AND fs.is_online = 1
                LIMIT ?
                """,
                (file_path, K - active_replicas)
                )
            file_servers = cursor.fetchall()
        
        except sqlite3.OperationalError as e:
            print(f"Error selecting record for file '{file_path}':", e)
        
        finally:
            conn.close()
        
        print(f"DEBUG. FILE SERVERS: {file_servers}")
        # If no file servers are available, continue.
        if not file_servers:
            print(f"No file servers available. Skipping file '{file_path}'.")
            
            continue
        else:
            # Send, if possible, other file servers' coordinate to the primary server.
            # Try to connect to the primary server.
            try:
                server = rpyc.connect(primary_server[0], primary_server[1])
                server.root.send_file_replicas(file_path, file_servers)
                print(f"Replication job for file '{file_path}' completed.")
            
            except Exception as e:
                print(f"Unable to connect to primary server: {e}.")
                continue
        
        # Update the replicas table.
        conn    = sqlite3.connect(DB_PATH)
        cursor  = conn.cursor()
        
        for file_server in file_servers:
            try:
                cursor.execute("""
                    INSERT INTO replicas (file_path, server)
                    VALUES (?, ?)
                    """,
                    (file_path, file_server[0])
                    )
                conn.commit()
            
            except sqlite3.OperationalError as e:
                print(f"Error inserting record for file '{file_path}':", e)
        
            finally:
                conn.close()



if __name__ == "__main__":
    print("Welcome to sym-DFS Project Server.")
    
    # Mantain K replicas.
    K = 2
    
    scheduler = BackgroundScheduler()
    scheduler.add_job(periodic_replication_job, args=[K], trigger='interval', seconds=30)
    scheduler.start()
    
    # Start the replication job in a separate thread.
    # replication_thread = threading.Thread(
    #     target=periodic_replication_job(K),
    #     daemon=True
    #     )
    
    # print("Starting periodic replication job...")
    # replication_thread.start()
    
    # Start the name server.
    server = ThreadedServer(NameServerService, port=SERVER_PORT)
        
    print("Starting name server...")
    server.start()

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



### Name server main class ###

class NameServerService(rpyc.Service):
    """
    Represents the name server, which is the central node in the sym-DFS architecture.
    The name server is a singleton.
    """
    
    # NOTE: sqlite3 è di default in modalità "serialized", ciò significa che si
    #       possono eseguire più thread in simultanea senza restrizioni.
    #       https://docs.python.org/3/library/sqlite3.html#sqlite3.threadsafety
    #       Il progetto si può estendere per supportare accesso concorrente al DB.
    # IMPROVE: per risparmiare codice si potrebbe trovare il modo di definire una
    #       funzione od un decoratore che nasconda i costrutti try-catch, esponendo
    #       solamente SQL queries e messaggi di errore.
    
    _instance           = None              # NameServerService active instance.
    _lock_file          = LOCKFILE_PATH     # File used to lock the file server.
    
    
    ##### DUNDER METHODS #####
    
    
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
        """
        Initializes the name server.
        Args:
            host (str): The hostname or IP address of the name server.
            port (int): The port number of the name server.
        """
        
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
    
    
    ##### PRIVATE METHODS #####
    
    
    def _setup_database(self):
        """
        Creates the nameserver's database (if it doesn't exist) and initializes it.
        """
        
        # NOTE: la creazione del database potrebbe anche essere svolta (quando
        #       necessario) al lancio del server nella funzione __main__.
        
        if os.path.exists(DB_PATH):
            print("Database already exists.")
            
            return
        
        # Create the database.
        print("Creating name server database...")
        
        conn    = sqlite3.connect(self.db_path)
        cursor  = conn.cursor()
        
        # Create users table.
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    is_root BOOLEAN NOT NULL DEFAULT 0,
                    is_online BOOLEAN NOT NULL DEFAULT 0,
                    last_heartbeat TIMESTAMP
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
                    is_corrupted BOOLEAN NOT NULL DEFAULT 0,
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
        Generates a JWT token for clients and file servers.
        Args:
            user_id (str):  The username or the server name.
            role (str):     The role of the entity.
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
        
        # IMPROVE: questa funzione si dovrebbe spostare nel pacchetto delle
        #          funzioni di utilità, aggiungendo il parametro per la chiave
        #          pubblica. Entrambi name server e file servers risparmierebbero
        #          la scrittura del codice.
        
        try:
            payload = jwt.decode(token, self._public_key, algorithms=["RS384"])
        
        except jwt.InvalidTokenError as e:
            print("Error decoding JWT token:", e)
            
            return None
        
        return payload
    
    
    ##### ENTITY MANAGEMENT RPCs #####
    
    
    # NOTE: la creazione di utenti e file servers vanno bene anche separate,
    #       in quanto signature e logica sono sufficientemente differenti.
    
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
                "status":   False,
                "message":  "Invalid root passphrase. Unauthorized action."
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
            "status":   True,
            "message":  f"User '{username}' created successfully."
            }
        
        except sqlite3.IntegrityError as e:
            print("Error creating user:", e)
            
            return {
                "status":   False,
                "message":  f"Error: user '{username}' already exists."
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
        
        # Verify that there are no conflicts with the name server.
        if host == "localhost" or host == "127.0.0.1":
            if int(port) == self.server_port:
                return f"Error: File server port {port} conflicts with name server port."
        
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
            print("Error creating file server:", e)
            
            return f"Error: file server '{name}' already exists."
        
        finally:
            conn.close()
    
    
    # NOTE: autenticazione di clients e file servers si potrebbero accorpare,
    #       perché la logica è piuttosto simile. Trattandosi però di due RPC
    #       abbastanza verbose, per ora le teniamo separate.
    
    def exposed_authenticate_user(self, username, password):
        """
        Authenticates a user and sends back a JWT token.
        Args:
            username (str): The username of the user.
            password (str): The password of the user.
        Returns:
            dict:           A dictionary containing the result of the operation.
        """
        
        # NOTE: sia la creazione che l'autenticazione di un utente root o regolare
        #       vengono fatte dalle stesse funzioni (per semplicità e risparmio di
        #       codice). Nella creazione ci siamo serviti della passphrase per
        #       assicurare un minimo di sicurezza. In questo caso supponiamo
        #       semplicemente che chi tenta di autenticarsi come root debba conoscere
        #       le credenziali.
        # IMPROVE: per rendere il progetto più sicuro si potrebbe implementare un
        #       numero massimo di tentativi di accesso.
        
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
            print("Error selecting record for user:", e)
            
            return {
                "status":   False,
                "message":  f"Error authenticating user '{username}'."
                }
        
        ### Check whether login can't be done.
        
        # Check user existence. User must exist.
        if result is None:
            conn.close()
            
            return {
                "status":   False,
                "message":  f"Error: user '{username}' not found."
                }
        
        # Check user online status. User must not be online.
        if result[0]:
            conn.close()
            
            return {
                "status":   False,
                "message":  f"Error: user '{username}' already logged in."
                }
        
        # Check user password validity. Password must be correct.
        password_match = checkpw(password.encode('utf-8'), result[1])
        
        if not password_match:
            conn.close()
            
            return {
                "status":   False,
                "message":  f"Error: wrong password for user '{username}'."
                }
        
        ### If the above checks are passed:
        
        # Check user root status. Create a token depending on the root status.
        if result[2]:
            token = self._generate_token(username, "root")
        else:
            token = self._generate_token(username, "regular")
        
        # Try to update user online status.
        try:
            cursor.execute("""
                UPDATE users
                SET is_online = 1,
                last_heartbeat = CURRENT_TIMESTAMP
                WHERE username = ?
                """,
                (username,)
                )
            conn.commit()
            
            return {
                "status":   True,
                "message":  f"User '{username}' authenticated successfully.",
                "token":    token
                }
        
        except sqlite3.OperationalError as e:
            print(f"Error updating record for user:", e)
            
            return {
                "status":   False,
                "message":  f"Error authenticating user '{username}'."
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
            print("Error selecting record for file server:", e)
            conn.close()
            
            return {
                "status":   False,
                "message":  f"Error connecting to the database."
                }
        
        ### Check whether login can't be done.
        
        # Check file server existence. File server must exist.
        if result is None:
            conn.close()
            
            return {
                "status":   False,
                "message":  f"Error: file server '{name}' not found."
                }
        
        # Check file server online status. File server must not be online.
        if result[0]:
            conn.close()
            
            return {
                "status":   False,
                "message":  f"Error: file server '{name}' already logged in."
                }
        
        # Check file server password validity. Password must be correct.
        password_match = checkpw(password.encode('utf-8'), result[1])
        
        if not password_match:
            conn.close()
            
            return {
                "status":   False,
                "message":  f"Error: wrong password for file server '{name}'."
                }
        
        ### If the above checks are passed:
        
        # Generate a token.
        token = self._generate_token(name, "file_server")
        
        # Try to update file server online status.
        try:
            cursor.execute("""
                UPDATE file_servers
                SET is_online = 1,
                last_heartbeat = CURRENT_TIMESTAMP
                WHERE name = ?
                """,
                (name,)
                )
            conn.commit()
            
            return {
                "status":       True,
                "message":      f"File server '{name}' authenticated successfully.",
                "host":         result[2],
                "port":         result[3],
                "token":        token,
                "public_key":   self._public_key
                }
        
        except sqlite3.OperationalError as e:
            print("Error updating record for file server:", e)
            
            return {
                "status":   False,
                "message":  f"Error connecting to the database."
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
        
        # TEST: cancellazione utente con files.
        
        conn    = sqlite3.connect(self.db_path)
        cursor  = conn.cursor()
        
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
            
            return "Error deleting user {username}."
        
        finally:
            conn.close()
    
    
    def exposed_logout(self, token):
        """
        Logs out an entity.
        Args:
            token (str):    The JWT token of the requestor.
        Returns:
            str:            A message indicating the result of the operation.
        """
        
        # NOTE: il logout è una RPC unica per clients e file servers, per
        #       rendere il codice piu' semplice.
        
        conn            = sqlite3.connect(self.db_path)
        cursor          = conn.cursor()
        
        # Get the username and the role from the token.
        payload         = self._get_token_payload(token)
        
        if payload is None:
            conn.close()
            
            return f"Error logging out. Corrupted token."
        
        username    = payload["username"]
        role        = payload["role"]
        
        # If the requestor is a file server, update its online status.
        if role == "file_server":
            try:
                cursor.execute("""
                    UPDATE file_servers
                    SET is_online = 0
                    WHERE name = ?
                    """,
                    (username,)
                    )
                conn.commit()
                
                return f"File server '{username}' logged out successfully."
            
            except sqlite3.OperationalError as e:
                print("Error updating record for file server:", e)
                conn.close()
                
                return f"Error logging out file server '{username}'."
            
            finally:
                conn.close()
        
        
        # Else, it must be a client, so update its online status.
        try:
            cursor.execute("""
                UPDATE users
                SET is_online = 0
                WHERE username = ?
                """,
                (username,)
                )
            conn.commit()
            
            return f"User '{username}' logged out successfully."
        
        except sqlite3.OperationalError as e:
            print("Error updating record for user:", e)
            conn.close()
            
            return f"Error logging out user '{username}'."
        
        finally:
            conn.close()
    
    
    ##### BASIC CLIENT RPCs #####
    
    
    def exposed_get_user_files(self, token):
        """
        Gets the files owned by a user for visualization purposes.
        Args:
            token (str):    The JWT token of the user.
        Returns:
            list:           A list of dictionaries containing the file information.
        """
        
        # TODO: rimuovere il checksum dalla visualizzazione dei file, oppure
        #       implementare una nuova visualizzazione con le repliche. Comunque,
        #       il meccanismo di replica dovrebbe essere trasparente agli utenti
        #       ed il checksum non è di interesse per l'uso del DFS a fini di
        #       storage.
        
        conn    = sqlite3.connect(self.db_path)
        cursor  = conn.cursor()
        
        # Get the username from the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            conn.close()
            
            return {
                "status":   False,
                "message":  "Error getting user files. Corrupted token."
                }
        
        username = payload["username"]
        
        # Get the files owned by the user.
        try:
            cursor.execute("""
                SELECT file_path, size, checksum, is_corrupted, uploaded_at, primary_server
                FROM files
                WHERE owner = ?
                """,
                (username,)
                )
            result = cursor.fetchall()
            
            # Check whether the user has any files.
            if not result:
                return {
                    "status":   False,
                    "message":  f"User '{username}' has no files."
                    }
            
            return {
                "status":   True,
                "message":  f"Files for user '{username}' retrieved successfully.",
                "files":    result
                }
        
        except sqlite3.OperationalError as e:
            print(f"Error selecting record for user:", e)
            
            return {
                "status":   False,
                "message":  f"Error retrieving files for user '{username}'."
                }
        
        finally:
            conn.close()
    
    
    def exposed_get_file_server_upload(self, token, file_path, file_size, checksum):
        """
        Gets the best file server to store a client's file according to K-least
        loaded policy. In this case load is the free space of the file server.
        Args:
            token (str):        The JWT token of the user.
            file_path (str):    The absolute file path in the DFS.
            file_size (int):    The size of the file.
            checksum (str):     The checksum of the file.
        Returns:
            dict:               A dictionary containing the file server information.
        """
        
        # Get the username from the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            return {
                "status":   False,
                "message":  f"Error getting user files. Corrupted token."
                }
        else:
            username = payload["username"]
        
        # Verify that the first directory has the same name as the username.
        if file_path.split("/")[0] != username:
            return {
                "status":   False,
                "message":  f"Error sending file. Base directory does not match username."
                }
        
        # Verify that the file path does not contain any '..'.
        if ".." in file_path:
            return {
                "status":   False,
                "message":  f"Error sending file. Invalid file path."
                }
        
        # Get the file's name.
        file_name = os.path.basename(file_path)
        
        # K is the number of file servers to randomly choose from.
        K = 3
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get the K least loaded file servers.
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
            conn.close()
            
            return {
                "status":   False,
                "message":  f"Error getting best file server for file '{file_name}'."
                }
        
        # Check if there is any file server available.
        if len(result) == 0:
            return {
                "status":   False,
                "message":  f"No file server available for file '{file_name}'."
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
                "status":   False,
                "message":  f"No file server has enough free space for file '{file_name}'."
            }
        
        # Update the file server's free space.        
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
            print("Error updating record for file server:", e)
            conn.close()
            
            return {
                "status":   False,
                "message":  f"Error updating file server for file '{file_name}'."
                }
        
        # Create new entry into the files table.
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
            conn.close()
            
            return {
                "status":   False,
                "message":  f"Error creating for file '{file_name}'."
                }
        
        # Create a new entry into the replicas table.
        try:
            cursor.execute("""
                INSERT INTO replicas (file_path, server)
                VALUES (?, ?)
                """,
                (file_path, best_file_server[0])
                )
            conn.commit()
            
            return {
            "status":   True,
            "message":  f"Best file server found.",
            "host":     best_file_server[1],
            "port":     best_file_server[2]
            }
        
        except sqlite3.OperationalError as e:
            print(f"Error inserting record for replica of file:", e)
            conn.close()
            
            return {
                "status":   False,
                "message":  f"Error creating replica for file '{file_name}'."
                }
        
        finally:
            conn.close()
    
    
    def exposed_get_file_server_download(self, token, file_path):
        """
        Gets the primary server for a client which wants to download a file.
        In case the primary file server is offline, the first online file server
        available is returned.
        Args:
            file_path (str):    The absolute file path in the DFS.
            token (str):        The JWT token of the requestor.
        Returns:
            dict:               A dictionary containing the file server information.
        """
        # TEST: download file da server primario e non.
        
        # Get the username from the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            return {
                "status":   False,
                "message":  f"Error getting file server. Corrupted token."
                }
        else:
            username = payload["username"]
        
        conn    = sqlite3.connect(self.db_path)
        cursor  = conn.cursor()
        
        # Get host and port of the primary file server for the file.
        try:
            cursor.execute("""
                SELECT f.primary_server, fs.address, fs.port
                FROM files AS f
                JOIN file_servers AS fs ON f.primary_server = fs.name
                WHERE f.file_path = ?
                AND f.owner = ?
                AND fs.is_online = 1
                """,
                (file_path, username)
                )
            result = cursor.fetchone()
        
        except sqlite3.OperationalError as e:
            print(f"Error selecting record for file:", e)
            conn.close()
            
            return {
                "status":   False,
                "message":  f"Error getting file server for file '{file_path}'."
                }
        
        # If the primary file server is available, return its information.
        if result:
            conn.close()
            
            return {
                "status":   True,
                "message":  f"Primary server found.",
                "host":     result[1],
                "port":     result[2]
                }
        
        
        # If not, look for an online file server to download the file.        
        try:
            cursor.execute("""
                SELECT fs.name, fs.address, fs.port
                FROM files AS f
                JOIN replicas AS r ON f.file_path = r.file_path
                JOIN file_servers AS fs ON r.server = fs.name
                WHERE file_path = ?
                AND fs.is_online = 1
                """,
                (file_path,)
                )
            result = cursor.fetchone()
        
        except sqlite3.OperationalError as e:
            print(f"Error selecting record for replica of file:", e)
            conn.close()
            
            return {
                "status":   False,
                "message":  f"Error getting file server for file '{file_path}'."
                }
            
        finally:
            conn.close()
        
        # If an online file server is available, return its information.
        if result:
            return {
                "status":   True,
                "message":  f"Online file server found.",
                "host":     result[1],
                "port":     result[2]
                }
        
        # If no file server is available, return an error message.
        return {
            "status":   False,
            "message":  f"Couldn't find an available file server for file '{file_path}'."
            }
    
    
    def exposed_delete_file(self, file_path, token):
        """
        Deletes a file from the DFS.
        Args:
            file_path (str):    The path of the file in the DFS.
            token (str):        The token of the requestor.
        """
        
        # NOTE: la cancellazione di un file, come la cancellazione di un utente,
        #       avviene solo lato-name server (più precisamente nel database).
        #       I files vengono effettivamente cancellati dai file servers
        #       tramite un meccanismo periodico di garbage cleaning.
        
        # TEST: cancellazione di un file con i nuovi meccanismi di replica e
        #       garbage cleaning attivi.
        
        # Get the username from the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            return f"Error deleting file. Corrupted token."
        else:
            username = payload["username"]
        
        conn    = sqlite3.connect(self.db_path)
        cursor  = conn.cursor()
        
        # Delete the file from the replicas table. 
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
            conn.close()
            
            return f"Error deleting replicas of file '{file_path}'."
        
        # Delete the file from the files table.        
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
    
    
    ##### ROOT CLIENT RPCs #####
    
    
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
    
    
    def exposed_list_all_files(self, token):
        """
        Lists all files in the DFS. For root clients use only.
        Args:
            token (str):    The token of the requestor.
        Returns:
            dict:           A dictionary with the status and the list of files.
        """
        
        # TEST: lista di tutti i files con un file corrotto nel database.
        
        # Get the client's role from the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            return {
                "status":   False,
                "message":  "Error listing files. Corrupted token."
                }
        
        role = payload["role"]
        
        # Check the role of the requestor. It must be root.
        if role != "root":
            return {
                "status":   False,
                "message":  "Error listing files. Only admin can list files."
                }
        
        conn    = sqlite3.connect(self.db_path)
        cursor  = conn.cursor()
        
        # Get the metadata of all files in the DFS.
        try:
            cursor.execute("""
                SELECT f.file_path, f.size, f.owner, f.checksum, f.is_corrupted, f.uploaded_at, r.server
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
            "status":   True,
            "message":  "Listing files",
            "files":    result
            }
    
    
    def exposed_list_all_clients(self, token):
        """
        Lists all clients in the DFS. For root clients use only.
        Args:
            token (str):    The token of the requestor.
        Returns:
            dict:           A dictionary with the status and the list of clients.
        """
        
        # NOTE: la lista di tutti i files, di tutti i clients e di tutti i file
        #       servers è effettivamente un po' boilerplate. Si potrebbe definire
        #       una funzione che faccia tutte e 3 le cose, ma si tratterebbe
        #       di una soluzione meno modulare di quella attuale.
        
        # Get the client's role from the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            return {
                "status":   False,
                "message":  "Error listing clients. Corrupted token."
                }
        
        role = payload["role"]
        
        # Check the role of the client.
        if role != "root":
            return {
                "status":   False,
                "message":  "Error listing clients. Only admin can list clients."
                }
        
        conn    = sqlite3.connect(self.db_path)
        cursor  = conn.cursor()
        
        # Get the metadata of all clients in the DFS.
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
            "status":   True,
            "message":  "Listing clients",
            "clients":  result
            }
    
    
    def exposed_list_all_file_servers(self, token):
        """
        Lists all file servers in the DFS. For root clients use only.
        Args:
            token (str):    The token of the requestor.
        Returns:
            dict:           A dictionary with the status and the list of file servers.
        """
        
        # Get the client's role from the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            return {
                "status":   False,
                "message":  "Error listing file servers. Corrupted token."
                }
        
        role = payload["role"]
        
        # Check the role of the client.
        if role != "root":
            return {
                "status":   False,
                "message":  "Error listing file servers. Only admin can list file servers."
                }
        
        conn    = sqlite3.connect(self.db_path)
        cursor  = conn.cursor()
        
        # Get the metadata of all file servers in the DFS.
        try:
            cursor.execute("""
                SELECT name, is_online, address, port, size, free_space
                FROM file_servers
                """)
            result = cursor.fetchall()
        
        except sqlite3.OperationalError as e:
            print(f"Error selecting records for file servers:", e)
            
            return {
                "status:":  False,
                "message":  "Error listing file servers."
                }
        
        finally:
            conn.close()
        
        return {
            "status":       True,
            "message":      "Listing file servers",
            "file_servers": result
            }
    
    
    ##### PERIODIC JOBS AND HEARTBEATS HANDLING #####
    
    
    def exposed_receive_activity_heartbeat(self, token):
        """
        Updates the heartbeat timestamp of a client or file server.
        Args:
            token (str):    The token of the requestor.
        """
        
        # Get the requestor's username and role from the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            return f"Error updating heartbeat. Corrupted token."
        
        username    = payload["username"]
        role        = payload["role"]
        
        conn        = sqlite3.connect(self.db_path)
        cursor      = conn.cursor()
        
        # If the requestor is a file server, update its last heartbeat.
        if role == "file_server":
            try:
                cursor.execute("""
                    UPDATE file_servers
                    SET last_heartbeat = datetime('now')
                    WHERE name = ?  
                    """,
                    (username, )
                    )
                conn.commit()
            
            except sqlite3.OperationalError as e:
                print(f"Error updating record for file server:", e)
            
            finally:
                conn.close()
        
        # Else the requestor is a client, so update its last heartbeat.
        try:
            cursor.execute("""
                UPDATE users
                SET last_heartbeat = datetime('now')
                WHERE username = ?  
                """,
                (username,)
                )
            conn.commit()
        
        except sqlite3.OperationalError as e:
            print(f"Error updating record for client:", e)
        
        finally:
            conn.close()
    
    
    def exposed_handle_file_inconsistency(self, token, file_path):
        """
        Takes actions to handle a file inconsistency found in a file server.
        Args:
            token (str):        The JWT token of the file server.
            file_path (str):    The path of the file in the DFS.
        """
        
        # Get the requestor's username and role from the token.
        payload = self._get_token_payload(token)
        
        if payload is None:
            return f"Error handling file inconsistency. Corrupted token."
        
        role    = payload["role"]
        name    = payload["username"]
        
        # DEBUG
        print(f"Handling file inconsistency for file '{file_path}' on file server '{name}'...")
        
        # Verify the requestor is a file server.
        if role != "file_server":
            return f"Error handling file inconsistency. Requestor is not a file server."
        
        ### Handle the inconsistency.
        
        conn    = sqlite3.connect(self.db_path)
        cursor  = conn.cursor()
        
        # Select the primary file server for the file.
        try:
            cursor.execute("""
                SELECT primary_server
                FROM files
                WHERE file_path = ?
                """,
                (file_path, )
                )
            primary_server = cursor.fetchone()[0]
            
        except sqlite3.OperationalError as e:
            print(f"Error selecting primary server:", e)
            conn.close()
            
            return f"Error getting the primary serfer for file '{file_path}'"
        
        # If the requestor was not the primary file server for the file, just
        # remove the replica from the database.
        # If the requestor was the primary file server for the file, remove the
        # replica from the database then try to find a new primary file server.
        
        # Basically, we need to delete the replica in any way.
        try:
            cursor.execute("""
                DELETE FROM replicas
                WHERE file_path = ? AND server = ?
                """,
                (file_path, name)
                )
            conn.commit()
        
        except sqlite3.OperationalError as e:
            print(f"Error deleting replica:", e)
            conn.close()
            
            return f"Error removing replica for file '{file_path}'"
        
        # If the requestor was not the primary server for the file, just return.
        if name != primary_server:
            conn.close()
            
            return f"Replica for file '{file_path}' removed successfully."
        
        # First, try to find a new primary file server among online file servers.
        try:
            cursor.execute("""
                SELECT fs.name
                FROM files AS f
                JOIN replicas AS r ON f.file_path = r.file_path
                JOIN file_servers AS fs ON r.server = fs.name
                WHERE fs.is_online = 1
                AND f.file_path = ?
                LIMIT 1
                """,
                (file_path, )
                )
            new_primary_server = cursor.fetchone()
        
        except sqlite3.OperationalError as e:
            print(f"Error selecting new primary server:", e)
            conn.close()
            
            return f"Error getting the new primary serfer for file '{file_path}'"
        
        # If an online file server was found, update the primary server for
        # the file.
        if new_primary_server:
            # Get the name of the new primary file server (query result is a tuple).
            new_primary_server = new_primary_server[0]
            
            # DEBUG
            print("New primary server (online):", new_primary_server)
            
            try:
                cursor.execute("""
                    UPDATE files
                    SET primary_server = ?
                    WHERE file_path = ?
                    """,
                    (new_primary_server, file_path)
                    )
                conn.commit()
            
            except sqlite3.OperationalError as e:
                print(f"Error updating primary server:", e)
                conn.close()
                
                return f"Error updating the primary server for file '{file_path}'"
        
            conn.close()
            
            return f"Primary server for file '{file_path}' updated successfully."
        
        # If no online file server was found, try to find one offline.
        try:
            cursor.execute("""
                SELECT fs.name
                FROM files AS f
                JOIN replicas AS r ON f.file_path = r.file_path
                JOIN file_servers AS fs ON r.server = fs.name
                WHERE fs.is_online = 0
                AND f.file_path = ?
                LIMIT 1
                """,
                (file_path, )
                )
            new_primary_server = cursor.fetchone()
        
        except sqlite3.OperationalError as e:
            print(f"Error selecting new primary server:", e)
            conn.close()
            
            return f"Error getting the new primary serfer for file '{file_path}'"
        
        # If an offline primary file server was found, update the primary server
        # for the file.
        if new_primary_server:
            # Get the name of the new primary file server (query result is a tuple).
            new_primary_server = new_primary_server[0]
            
            # DEBUG
            print("New primary server (offline):", new_primary_server)
            
            try:
                cursor.execute("""
                    UPDATE files
                    SET primary_server = ?
                    WHERE file_path = ?
                    """,
                    (new_primary_server, file_path)
                    )
                conn.commit()
            
            except sqlite3.OperationalError as e:    
                print(f"Error updating primary server:", e)
                conn.close()
                
                return f"Error updating the primary server for file '{file_path}'"
        
        # Eventually, if no new primary file server was found, mark the file as
        # corrupted.
        
        # DEBUG
        print("No new primary server found. Marking file as corrupted...")
        
        try:
            cursor.execute("""
                UPDATE files
                SET is_corrupted = 1
                WHERE file_path = ?
                """,
                (file_path, )
                )
            conn.commit()
        
        except sqlite3.OperationalError as e:
            print(f"Error marking file as corrupted:", e)
            conn.close()
            
            return f"Error marking file '{file_path}' as corrupted"
        
        conn.close()
        
        return f"File '{file_path}' marked as corrupted successfully."


##### PERIODIC JOBS #####

# Pulizia del codice ok fino qua <-----


def periodic_replication_job(K):
    """
    Periodically replicates the files in the DFS up to K times.
    Args:
        K (int):    The number of times to replicate the files.
    """
    
    print("Replicating files...")
    
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
    
    except sqlite3.OperationalError as e:
        print(f"Error selecting records for replication:", e)
        conn.close()
        
        return
    
    # If there are no files to replicate, return.
    if not files_to_replicate:
        conn.close()
        
        return
    
    # For every file that needs to be replicated.
    for file_path, active_replicas in files_to_replicate:
        
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
            print(f"Error selecting record:", e)
            conn.close()
            
            return
        
        # If the primary server is offline, continue.
        if not primary_server:
            print(f"File server is offline. Skipping file '{file_path}'.")
            
            continue
        
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
            conn.close()
            
            return
        
        # If no file servers are available, continue.
        if not file_servers:
            print(f"No file servers available. Skipping replication for file '{file_path}'.")
            
            continue
        else:
            # Send file servers' coordinates to the primary server if possible.
            # Try to connect to the primary server.
            try:
                server = rpyc.connect(primary_server[0], primary_server[1])
                server.root.send_file_replicas(file_path, file_servers)
                print(f"Replication job for file '{file_path}' completed.")
            
            except Exception as e:
                print(f"Unable to connect to primary server: {e}.")
                conn.close()
                
                return
        
        # Update the replicas table.
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
                conn.close()
                
                return
    
    conn.close()


def periodic_check_activity(hb_timeout):
    """
    Periodically checks the activity of the other entities in the DFS.
    Updates the status of the file servers and users if they haven't sent
    a heartbeat in the last hb_timeout seconds.
    Args:
        hb_timeout (int):   The maximum time since the last heartbeat.
    """
    
    # NOTE: sebbene sia stata implementata la disconnessione logica sul database
    #       in ogni client e file server, è possibile che il name server venga
    #       disconnesso in modo improvviso prima che le altre componenti possano
    #       a loro volta disconnettersi in modo sicuro. In casi come questo,
    #       clients e file servers permangono nel database come connessi.
    #       Il presente meccanismo forza la disconnessione logica (su database)
    #       di tutti i clients e file servers che non hanno inviato un heartbeat
    #       nel periodo definito.
    
    print("Checking system entities activity...")
    
    conn    = sqlite3.connect(DB_PATH)
    cursor  = conn.cursor()
    
    # Update the status in the file servers table.
    try:
        cursor.execute("""
            UPDATE file_servers
            SET is_online = 0
            WHERE is_online = 1
            AND (strftime('%s', 'now') - strftime('%s', last_heartbeat)) > ?
            """,
            (hb_timeout, )
            )
        conn.commit()
    
    except sqlite3.OperationalError as e:
        print(f"Error updating file servers status:", e)
        conn.close()
        
        return
    
    # Update the status in the users table.
    try:
        cursor.execute("""
            UPDATE users
            SET is_online = 0
            WHERE is_online = 1
            AND (strftime('%s', 'now') - strftime('%s', last_heartbeat)) > ?
            """,
            (hb_timeout, )
            )
        conn.commit()
    
    except sqlite3.OperationalError as e:
        print(f"Error updating users status:", e)
        conn.close()
        
        return
    
    conn.close()


def periodic_trigger_garbage_collection():
    """
    Periodically sends to the active file servers the files they should have,
    so that they can delete those files and directories that are not needed
    anymore.
    """
    
    print("Triggering garbage collection on active file servers...")
    
    conn    = sqlite3.connect(DB_PATH)
    cursor  = conn.cursor()
    
    # Select all the file servers that are online.
    try:
        cursor.execute("""
            SELECT name, address, port
            FROM file_servers
            WHERE is_online = 1
            """)
        file_servers = cursor.fetchall()
    
    except sqlite3.OperationalError as e:
        print(f"Error selecting record for online file servers:", e)
        conn.close()
        
        return
    
    # For every online file server.
    for file_server in file_servers:
        
        # Select all the files that are stored in that node, according to the
        # database.
        try:
            cursor.execute("""
                SELECT file_path
                FROM replicas
                WHERE server = ?
                """,
                (file_server[0], )
                )
            files = cursor.fetchall()
        
        except sqlite3.OperationalError as e:
            print(f"Error selecting record for replicas:", e)
            conn.close()
            
            return
        
        # If there are no files for this file server, continue.
        if not files:
            continue
        
        # Send the files to the file server.
        try:
            server = rpyc.connect(file_server[1], file_server[2])
            server.root.garbage_collection(files)
        
        except Exception as e:
            print(f"Unable to connect to file server: {e}.")
            conn.close()
            
            return
    
    conn.close()
    
    return


def periodic_trigger_consistency_check():
    """
    Periodically sends to the active file servers the files they should have
    and their checksums, so that they can check the consistency of the files
    they store.
    """
    
    print("Triggering consistency check on active file servers...")
    
    conn    = sqlite3.connect(DB_PATH)
    cursor  = conn.cursor()
    
    # Select all the file servers that are online.
    try:
        cursor.execute("""
            SELECT name, address, port
            FROM file_servers
            WHERE is_online = 1
            """)
        file_servers = cursor.fetchall()
    
    except sqlite3.OperationalError as e:
        print(f"Error selecting online file servers:", e)
        conn.close()
        
        return
    
    # For every online file server.
    for file_server in file_servers:
        
        # Select all the files that are stored in that node and their checksums,
        # according to the database.
        try:
            cursor.execute("""
                SELECT f.file_path, f.checksum
                FROM replicas AS r
                JOIN files AS f ON r.file_path = f.file_path
                WHERE r.server = ?
                """,
                (file_server[0], )
                )
            files = cursor.fetchall()
        
        except sqlite3.OperationalError as e:
            print(f"Error selecting replicas:", e)
            
            return
        
        # If there are no files for this file server, continue.
        if not files:
            continue
        
        # Send the files to the file server.
        try:
            server = rpyc.connect(file_server[1], file_server[2])
            server.root.consistency_check(files)
        
        except Exception as e:
            print(f"Unable to connect to file server: {e}.")
            conn.close()
            
            return
    
    conn.close()



if __name__ == "__main__":
    print("Welcome to sym-DFS Project Server.")
    
    # Mantain K replicas.
    K = 2
    # Receive heart-beats every HB_TIMEOUT seconds.
    HB_TIMEOUT = 30
    
    scheduler = BackgroundScheduler()
    
    print("Starting periodic replication job...")
    scheduler.add_job(
        periodic_replication_job,
        args=[K],
        trigger='interval',
        seconds=30
        )
    
    print("Starting periodic check activity job...")
    scheduler.add_job(
        periodic_check_activity,
        args=[HB_TIMEOUT],
        trigger='interval',
        seconds=30
        )
    
    print("Starting periodic garbage collection job...")
    scheduler.add_job(
        periodic_trigger_garbage_collection,
        trigger='interval',
        seconds=30
    )
    
    print("Starting periodic consistency check job...")
    scheduler.add_job(
        periodic_trigger_consistency_check,
        trigger='interval',
        seconds=30
    )
    
    scheduler.start()
    
    # Start the name server.
    server = ThreadedServer(NameServerService, port=SERVER_PORT)
    
    print("Starting name server...")
    server.start()

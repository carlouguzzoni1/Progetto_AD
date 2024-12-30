import os
import shutil
import sqlite3
import rpyc
from bcrypt import hashpw, gensalt, checkpw



LOCKFILE_PATH   = "./NS/nameserver.lock"
DB_PATH         = "./NS/NS.db"
SERVER_PORT     = 18861



class NameServerService(rpyc.Service):
    """
    Represents the name server, which is the central node in the sym-DFS architecture.
    Name server is a singleton.
    """    
    # TODO: implementare upload (dfs).
    # NOTE: Nell'upload occorre load balancing con K-least loaded (sulla base
    #       dello spazio disponibile).
    # TODO: implementare download (dfs).
    # NOTE: Nel download, imporre un controllo sul proprietario del file.
    
    # CHECKDOC: NameServerService esegue atomicamente i metodi RPC?
    # CHECKDOC: NameServerService necessita di programmazione concorrente esplicita?
    
    # IMPROVE: dovrebbero essere i clients/file servers a creare localmente
    #          la directory dedicata ai propri files.
    # IMPROVE: è necessario salvare le directory sul database locale del  name server?
    # NOTE: tutte le entità (escluso il name server) potrebbero avere una directory
    #       predefinita per i propri files.
    
    # TODO: inserire meccanismo di heart-beat per spegnere logicamente file servers
    #       ed utenti disconnessi con una procedura non regolare (dfs).
    
    _instance   = None          # NameServerService active instance.
    _lock_file  = LOCKFILE_PATH # File used to lock the file server.
    
    
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
        self.db_path        = DB_PATH
        self.server_port    = port
        
        self._setup_database()
    
    
    def __del__(self):
        """Removes the lock file when the name server is deleted."""
        
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
            
            # Many NOT NULL constraints should be used because most data is mandatory.
            # Sym-DFS software does still handle all mandatory data inherently.
            
            # Create users table.
            try:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        password_hash TEXT NOT NULL,
                        is_root BOOLEAN DEFAULT 0,
                        is_online BOOLEAN DEFAULT 0,
                        directory TEXT
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
                        is_online BOOLEAN DEFAULT 0,
                        size INTEGER,
                        directory TEXT,
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
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT UNIQUE NOT NULL,
                        size INTEGER,
                        checksum TEXT,
                        owner TEXT,
                        primary_server TEXT,
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
                        file_id INTEGER,
                        server TEXT,
                        FOREIGN KEY (file_id) REFERENCES files (id),
                        FOREIGN KEY (server) REFERENCES file_servers (name),
                        PRIMARY KEY (file_id, server)
                    );
                """)
            except sqlite3.OperationalError as e:
                print("Error creating replicas table:", e)
            
            conn.commit()            
            conn.close()
            
            print("Database created.")
    
    
    def exposed_create_user(self, username, password, is_root=False):
        """
        Creates a new user.
        Args:   
            username (str): The username of the new user.
            password (str): The password of the new user.
            is_root (bool): Whether the new user is a root user.
        Returns:
            dict:           A dictionary containing the result of the operation
                            and a message.
        """
        
        conn            = sqlite3.connect(self.db_path)
        cursor          = conn.cursor()
        hashed_password = hashpw(password.encode('utf-8'), gensalt())
        directory       = "./CLI/" + username
        
        # Create the user.
        try:
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, is_root, is_online, directory)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, hashed_password, is_root, False, directory)
            )
            conn.commit()
        
        except sqlite3.IntegrityError as e:
            print(f"Error creating user '{username}':", e)
            
            return {
                "status": False,
                "message": f"Error: user '{username}' already exists."
                }
        
        finally:
            conn.close()
        
        # Create the directory for the user.
        os.mkdir(directory)
        
        return {
            "status": True,
            "message": f"User '{username}' created successfully."
            }
    
    
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
        directory       = "./FS/" + name
        
        # Verify conflicts with the ame server.
        if host == "localhost" or host == "127.0.0.1":
            if port == self.server_port:
                return f"Error: File server port {port} conflicts with Name Server port."
        
        # Create the file server.
        try:
            cursor.execute("""
                INSERT INTO file_servers (name, password_hash, address, port, size)
                VALUES (?, ?, ?, ?, ?)
                """,
                (name, hashed_password, host, port, size)
                )
            conn.commit()
        
        except sqlite3.IntegrityError as e:
            print(f"Error creating file server '{name}':", e)
            
            return f"Error: file server '{name}' already exists."
        
        finally:
            conn.close()
        
        # Create the directory for the file server.
        os.mkdir(directory)
        
        return f"File server '{name}' created successfully."
    
    
    def exposed_authenticate_user(self, username, password, is_root=False):
        """
        Authenticates a user.
        Args:
            username (str): The username of the user.
            password (str): The password of the user.
            is_root (bool): Whether the user is a root user.
        Returns:
            dict:           A dictionary containing the result of the operation.
        """
        
        conn    = sqlite3.connect(self.db_path)
        cursor  = conn.cursor()
        
        # Get user online status, hashed password and directory.
        try:
            cursor.execute("""
                SELECT is_online, password_hash, directory, is_root
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
        
        # Check user root status. Can authenticate root user only when is_root is True.
        # Root user trying to authenticate a non-root user.
        if is_root and not result[3]:
            conn.close()
            
            return {
                "status": False,
                "message": f"Error: user '{username}' is not a root user."
                }
        
        # Non-root user trying to authenticate a root user.
        if not is_root and result[3]:
            conn.close()
            
            return {
                "status": False,
                "message": f"Error: user '{username}' is a root user."}
        
        # If login can be done (checks passed successfully).
        
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
        
        except sqlite3.OperationalError as e:
            print(f"Error updating record for user '{username}':", e)
            
            return {
                "status": False,
                "message": f"Error authenticating user '{username}'."
                }
        
        finally:
            conn.close()
        
        return {
            "status": True,
            "message": f"User '{username}' authenticated successfully.",
            "directory": result[2]
            }
    
    
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
        
        # Get file server online status, hashed password and directory.
        try:
            cursor.execute("""
                SELECT is_online, password_hash, directory, address, port
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
        
        except sqlite3.OperationalError as e:
            print(f"Error updating record for file server '{name}':", e)
            
            return {
                "status": False,
                "message": f"Error connecting to the database."
                }
        
        finally:
            conn.close()
        
        return {
            "status": True,
            "message": f"File server '{name}' authenticated successfully.",
            "directory": result[2],
            "host": result[3],
            "port": result[4]
            }
    
    
    def exposed_delete_user(self, username, password):
        """
        Deletes a user.
        Args:
            username (str): The username of the user.
            password (str): The password of the user.
        Returns:
            str:            A message indicating the result of the operation.
        """
        
        conn            = sqlite3.connect(self.db_path)
        cursor          = conn.cursor()
        
        # Get user root status, hashed password, online status and directory.
        try:            
            cursor.execute("""
                SELECT is_root, password_hash, is_online, directory
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
        
        # Get user directory.
        directory = result[3]
        
        # Delete the user.
        try:
            cursor.execute(
                """
                DELETE FROM users WHERE username = ?
                """,
                (username,)
                )
            conn.commit()
        
        except sqlite3.OperationalError as e:
            print("Error deleting record for user:", e)
            conn.close()
            
            return f"Error deleting user."
        
        finally:
            conn.close()
        
        # Delete the user directory.
        shutil.rmtree(directory)
        
        return f"User '{username}' deleted successfully."
    
    
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
    
    
    def exposed_logout(self, username):
        """
        Logs out a user.
        Args:
            username (str): The username of the user.
        Returns:
            str:            A message indicating the result of the operation.
        """
        
        conn        = sqlite3.connect(self.db_path)
        cursor      = conn.cursor()
        
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



if __name__ == "__main__":
    from rpyc.utils.server import ThreadedServer
    
    server = ThreadedServer(NameServerService, port=SERVER_PORT)
    
    print("Welcome to sym-DFS Project Server.")
    print("Starting name server...")
    server.start()

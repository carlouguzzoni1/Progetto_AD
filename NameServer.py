import os
import shutil
import sqlite3
import rpyc
from bcrypt import hashpw, gensalt, checkpw



DB_PATH     = "./NS/NS.db"
SERVER_PORT = 18861



class NameServerService(rpyc.Service):
    """
    Implements the name server, which:
    - Mantains a database with user, file and server information
    To-do: finire documentazione.
    """

    def __init__(self, host="localhost", port=SERVER_PORT):
        self.db_path        = DB_PATH
        self.server_port    = port
        self._setup_database()
        # To-do: inserire procedura di inizializzazione dei file servers presenti nel database.


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
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    is_root BOOLEAN DEFAULT 0,
                    is_online BOOLEAN DEFAULT 0,
                    directory TEXT
                );
            """)
            
            # To-do: aggiungere le altre tabelle - file servers/metadati?
            
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
            str:            A message indicating the result of the operation.
        """
        
        conn            = sqlite3.connect(self.db_path)
        cursor          = conn.cursor()
        hashed_password = hashpw(password.encode('utf-8'), gensalt())
        directory       = "./CLI/" + username
        
        try:
            # Create the user.
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, is_root, is_online, directory)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, hashed_password, is_root, False, directory)
            )
            conn.commit()
            # Create the directory for the user.
            os.mkdir(directory)
            return f"User '{username}' created successfully."
        except sqlite3.IntegrityError:
            return f"Error: user '{username}' already exists."
        finally:
            conn.close()


    def exposed_authenticate(self, username, password):
        """
        Authenticates a user.
        Args:
            username (str): The username of the user.
            password (str): The password of the user.
        Returns:
            dict:           A dictionary containing the result of the operation.
        """
        
        # To-do: aggiungere controllo on-line/off-line?
        conn    = sqlite3.connect(self.db_path)
        cursor  = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result  = cursor.fetchone()
        
        report = dict()
        
        if result is None:
            report["status"]    = False
            report["message"]   = f"Error: user '{username}' not found."
            return report
        
        # Check password.
        password_match = checkpw(password.encode('utf-8'), result[0])
        
        # Get user directory.
        cursor.execute("SELECT directory FROM users WHERE username = ?", (username,))
        directory = cursor.fetchone()[0]
        
        if password_match:
            report["status"]    = True
            report["message"]   = f"User '{username}' authenticated successfully."
            report["directory"] = directory
        else:
            report["status"]    = False
            report["message"]   = f"Error: wrong password for user '{username}'."
        
        conn.close()
        
        return report


    def exposed_delete_user(self, username, password):
        """
        Deletes a user.
        Args:
            username (str): The username of the user.
            password (str): The password of the user.
        Returns:
            str:            A message indicating the result of the operation.
        """
        
        # To-do: cancellazione non funziona. Debug.
        conn            = sqlite3.connect(self.db_path)
        cursor          = conn.cursor()
        hashed_password = hashpw(password.encode('utf-8'), gensalt())
        
        report = dict()
        
        try:
            # Get user directory.
            cursor.execute("SELECT directory FROM users WHERE username = ?", (username,))
            directory = cursor.fetchone()[0]
            # Delete the user.
            cursor.execute(
                """
                DELETE FROM users WHERE username = ? AND password_hash = ?
                """,
                (username, hashed_password)
            )
            conn.commit()
            # Delete user directory.
            shutil.rmtree(directory)
            return f"User '{username}' deleted successfully."
        except sqlite3.IntegrityError:
            return f"Error: user '{username}' not found or wrong password."
        finally:
            conn.close()



if __name__ == "__main__":
    from rpyc.utils.server import ThreadedServer
    
    server = ThreadedServer(NameServerService, port=SERVER_PORT)
    print("Welcome to sym-DFS Project Server.")
    print("Starting name server...")
    server.start()

import os
import shutil
import sqlite3
import rpyc
from bcrypt import hashpw, gensalt, checkpw



DB_PATH     = "./NS/NS.db"
SERVER_PORT = 18861



class NameServerService(rpyc.Service):
    """
    Represents the name server.
    TODO: finire documentazione.
    """

    def __init__(self, host="localhost", port=SERVER_PORT):
        self.db_path        = DB_PATH
        self.server_port    = port
        self._setup_database()
        # TODO: inserire procedura di inizializzazione dei file servers presenti nel database.


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
            
            # TODO: aggiungere le altre tabelle - file servers/metadati?
            
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
        
        conn    = sqlite3.connect(self.db_path)
        cursor  = conn.cursor()
        report  = dict()
        
        # Get user online status, hashed password and directory.
        try:
            cursor.execute("""
                SELECT is_online, password_hash, directory
                FROM users
                WHERE username = ?
                """,
                (username,)
                )
            result  = cursor.fetchone()
        except sqlite3.DatabaseError as e:
            # Generic database error.
            print(e)
            report["status"]    = False
            report["message"]   = f"Error connecting to the database."
            return report
        
        # Check whether login can't be done.
        # If user doesn't exist.
        if result is None:
            report["status"]    = False
            report["message"]   = f"Error: user '{username}' not found."
            conn.close()
            return report
        # Check user online status.
        if result[0]:
            report["status"]    = False
            report["message"]   = f"Error: user '{username}' already logged in."
            conn.close()
            return report
        # Check user password validity.
        password_match = checkpw(password.encode('utf-8'), result[1])
        if not password_match:
            report["status"]    = False
            report["message"]   = f"Error: wrong password for user '{username}'."
            conn.close()
            return report
        
        # If login can be done.
        report["status"]        = True
        report["message"]       = f"User '{username}' authenticated successfully."
        report["directory"]     = result[2]
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
        except sqlite3.DatabaseError as e:
            # Generic database error.
            print(e)
            report["status"]    = False
            report["message"]   = f"Error connecting to the database."
            conn.close()
            return report
        
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
        
        conn            = sqlite3.connect(self.db_path)
        cursor          = conn.cursor()
        hashed_password = hashpw(password.encode('utf-8'), gensalt())
        
        try:
            # Get user root status, hashed password, online status and directory.
            cursor.execute("""
                SELECT is_root, password_hash, is_online, directory
                FROM users
                WHERE username = ?
                """,
                (username,)
                )
            result = cursor.fetchone()
            # Check user existence.
            if result is None:
                conn.close()
                return f"Error: user '{username}' not found."
            # Check user root status.
            if result[0]:
                conn.close()
                return f"Error: you don't have the needed permissions to delete user '{username}'."
            # Check user online status.
            if result[2]:
                conn.close()
                return f"Error: user '{username}' is currently logged in."
            # Check user password validity.
            password_match = checkpw(password.encode('utf-8'), result[1])
            if not password_match:
                conn.close()
                return f"Error: wrong password for user '{username}'."
            # Get user directory.
            directory = result[3]
            # Delete the user.
            cursor.execute(
                """
                DELETE FROM users WHERE username = ?
                """,
                (username,)
                )
            conn.commit()
            # Delete the user directory.
            shutil.rmtree(directory)
            conn.close()
            return f"User '{username}' deleted successfully."
        except sqlite3.DatabaseError as e:
            # Generic database error.
            print(e)
            conn.close()
            return f"Error deleting user."



if __name__ == "__main__":
    from rpyc.utils.server import ThreadedServer
    
    server = ThreadedServer(NameServerService, port=SERVER_PORT)
    print("Welcome to sym-DFS Project Server.")
    print("Starting name server...")
    server.start()

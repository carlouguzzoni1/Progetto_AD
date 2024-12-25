import os
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

    def __init__(self):
        self.db_path        = DB_PATH
        self.server_port    = SERVER_PORT
        self._setup_database()
        # To-do: inserire procedura di inizializzazione dei file servers
        # presenti nel database.


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
            # Users table.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    is_root BOOLEAN DEFAULT 0
                );
            """)
            
            # To-do: aggiungere le tabelle relative a:
            # - File servers
            # - File e metadati
            
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
        """
        conn            = sqlite3.connect(self.db_path)
        cursor          = conn.cursor()
        hashed_password = hashpw(password.encode('utf-8'), gensalt())

        try:
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, is_root)
                VALUES (?, ?, ?)
                """,
                (username, hashed_password, is_root)
            )
            conn.commit()
            return f"User '{username}' created successfully."
        except sqlite3.IntegrityError:
            return f"Error: user '{username}' already exists."
        finally:
            conn.close()


"""
    def exposed_list_users(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT username, is_root FROM users")
        users = cursor.fetchall()
        conn.close()
        return [{"username": u[0], "is_root": bool(u[1])} for u in users] """



if __name__ == "__main__":
    from rpyc.utils.server import ThreadedServer
    
    server = ThreadedServer(NameServerService, port=SERVER_PORT)
    print("Welcome to sym-DFS Project Server.")
    print("Starting name server...")
    server.start()

import getpass
import os
import sys
from BaseClient import BaseClient
from getpass import getpass



class RegularClient(BaseClient):
    """Client class for regular users."""
    
    # NOTE: il regular client è pensato per essere un utente generico del DFS.
    #       Le funzionalità sono pertanto quelle di base, definite nella classe
    #       BaseClient, più i metodi che consenstono l'interazione con l'utente.
    
    def __init__(self, host, port):
        """
        Initializes the client.
        Args:
            host (str): The hostname or IP address of the name server.
            port (int): The port number of the name server.
        """
        
        super().__init__(host, port)
    
    
    def display_commands(self):
        """Displays the available commands for the regular clients."""
        
        print("""
        Welcome to sym-DFS Project Client.
        Commands:
        login               Log in as a user
        logout              Log out
        create-user         Create a new user
        delete-user         Delete a user
        list-files          List files of the user
        upload              Upload a file
        download            Download a file
        delete-file         Delete a file
        exit                Exit the program
        show-commands       Show commands
        """)
    
    
    def login(self):
        """Authenticates a regular user."""
        
        # Check whether a user is already logged in.
        if self.user_is_logged:
            print("Cannot login: an user is already logged in.")
            return
        
        username    = input("Insert username: ")
        password    = getpass("Insert password: ")
        result      = self.conn.root.authenticate_user(username, password)
        
        if result["status"]:
            self.user_is_logged     = True
            self.logged_username    = username
            self.files_dir          = "./CLI/{}".format(username)
            self.token              = result["token"]
            
            # Check whether the client actually has a local files directory.
            if not os.path.exists(self.files_dir):
                os.mkdir(self.files_dir)   # Create the directory.
        
        print(result["message"])
    
    
    def logout(self):
        """Logs out the current user."""
        
        if self.user_is_logged:
            # Update the user status in the name server's database.
            result = self.conn.root.logout(self.token)
            # Reset the client's state.
            self.user_is_logged     = False
            self.logged_username    = None
            self.files_dir          = None
            self.token              = None
            print(result)
        else:
            print("No user is logged in.")
    
    
    def main_prompt(self):
        """Main prompt for regular clients."""
        
        self.connect()              # Connect to the name server.
        self.display_commands()     # Display the available commands.
        
        while True:
            # Get user input.
            command = input(
                "({})> ".format(self.logged_username if self.user_is_logged else "non-auth")
            )
            
            # Execute the command.
            match command:
                case "login":
                    self.login()
                case "logout":
                    self.logout()
                case "create-user":
                    self.create_user()
                case "delete-user":
                    self.delete_user()
                case "list-files":
                    self.list_files()
                case "upload":
                    self.upload()
                case "download":
                    self.download()
                case "delete-file":
                    self.delete()
                case "exit":
                    print("Exiting...")
                    # Log out before exiting.
                    self.logout()
                    # Close the connection.
                    self.conn.close()
                    break
                case "show-commands":
                    self.display_commands()
                case _:
                    print("Unknown command. Type 'show-commands' for a list of commands.")



if __name__ == "__main__":
    client = RegularClient(sys.argv[1], int(sys.argv[2]))
    
    client.main_prompt()
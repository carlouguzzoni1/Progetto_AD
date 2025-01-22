import getpass
import os
import sys
from BaseClient import BaseClient
from getpass import getpass
import heartbeats
from apscheduler.schedulers.background import BackgroundScheduler
import utils
from functools import partial
import signal



CLIENT_BASE_DIR = "./CLI"



class RegularClient(BaseClient):
    """Client class for regular users."""
    
    # NOTE: il regular client è pensato per essere un utente generico del DFS.
    #       Le funzionalità sono pertanto quelle di base, definite nella classe
    #       BaseClient, più i metodi che consenstono l'interazione con l'utente.
    
    
    ##### DUNDER METHODS #####
    
    
    def __init__(self, host, port):
        """
        Initializes the client.
        Args:
            host (str): The hostname or IP address of the name server.
            port (int): The port number of the name server.
        """
        
        super().__init__(host, port)
    
    
    ##### ABSTRACT METHODS IMPLEMENTATION #####
    
    
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
                    self.logout()   # Log out before exiting.
                    # Connection is closed upon deletion, which happens on exit.
                    break
                case "show-commands":
                    self.display_commands()
                case _:
                    print("Unknown command. Type 'show-commands' for a list of commands.")
    
    
    ##### USER INTERACTION METHODS #####
    
    
    def login(self):
        """Authenticates a regular user."""
        
        # Check whether a user is already logged in.
        if self.user_is_logged:
            print("Cannot login: an user is already logged in.")
            return
        
        # Get username and password from the user.
        username    = input("Insert username: ")
        password    = getpass("Insert password: ")
        
        # Authenticate the user.
        result      = self.conn.root.authenticate_user(username, password)
        
        # Check whether the authentication was successful.
        if result["status"]:
            self.user_is_logged     = True
            self.logged_username    = username
            self.files_dir          = os.path.join(self.client_root_dir, username)
            self.token              = result["token"]
            self.scheduler          = BackgroundScheduler()
            
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
            
            # If this user doesn't have a directory, create it.
            if not os.path.exists(self.files_dir):
                os.mkdir(self.files_dir)
        
        print(result["message"])
    
    
    def logout(self):
        """Logs out the current user."""
        
        if self.user_is_logged:
            self._cleanup()
        else:
            print("No user is logged in.")



if __name__ == "__main__":
    
    # Create the client.
    client = RegularClient(sys.argv[1], int(sys.argv[2]))
    
    # Handle keyboard interrupts.
    signal.signal(signal.SIGINT, partial(utils.handle_keyboard_interrupt_client, client=client))
    
    # Prompt is displayed until user manually exits.
    client.main_prompt()
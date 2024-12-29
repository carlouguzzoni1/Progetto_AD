import sys
from BaseClient import BaseClient



class RegularClient(BaseClient):
    """Client class for regular users."""
    
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
        exit                Exit
        show-commands       Show commands
        """)
    
    
    def login(self):
        """Authenticates a regular user."""
        
        username    = input("Insert username: ")
        password    = input("Insert password: ")
        result      = self.conn.root.authenticate(username, password, False)
        
        if result["status"]:
            self.user_is_logged     = True
            self.logged_username    = username
            self.files_dir          = result["directory"]
        
        print(result["message"])
    
    
    def logout(self):
        """Logs out the current user."""
        
        if self.user_is_logged:
            # Update the user status in the name server's database.
            self.conn.root.logout(self.logged_username)
            # Reset the client's state.
            self.user_is_logged     = False
            self.logged_username    = None
            self.files_dir          = None
            print("Logged out successfully.")
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
                case "exit":
                    print("Exiting...")
                    # If the user is logged in, log out before exiting.
                    if self.user_is_logged:
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
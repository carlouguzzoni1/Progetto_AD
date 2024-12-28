from BaseClient import BaseClient



class RegularClient(BaseClient):
    """Client class for regular users."""
    # TODO: rimuovere i parametri di default nel metodo __init__ (app-starter).
    # TODO: usare i parametri da riga di comando (app-starter).
    # TODO: implementare visualizzazione stato dei propri files (dfs).
    # TODO: implementare upload (dfs).
    # TODO: implementare download (dfs).
    
    def __init__(self, host="localhost", port=18861):
        """
        Initializes the client.
        Args:
            host (str): The hostname or IP address of the name server.
            port (int): The port number of the name server.
        """
        super().__init__(host, port)
    
    
    def display_commands(self):
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
        result      = self.conn.root.authenticate(username, password)
        
        if result["status"]:
            self.user_is_logged     = True
            self.logged_username    = username
            self.files_dir          = result["directory"]
        
        print(result["message"])
    
    
    def logout(self):
        """Logs out the current user."""
        
        if self.user_is_logged:
            self.user_is_logged     = False
            self.logged_username    = None
            self.files_dir          = None
            print("Logged out successfully.")
        else:
            print("No user is logged in.")
    
    
    def create_user(self):
        """Creates a new regular user."""
        
        username = input("Insert username: ")
        password = input("Insert password: ")
        result = self.conn.root.create_user(username, password, False)
        print(result)
    
    
    def delete_user(self):
        """Deletes a regular user."""
        
        if not self.user_is_logged:
            print("You must be logged in to delete a user.")
        else:
            username = input("Insert username: ")
            password = input("Insert password: ")
            result = self.conn.root.delete_user(username, password)
            print(result)
    
    
    def main_prompt(self):
        """Main prompt for regular users."""
        
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
                    break
                case "show-commands":
                    self.display_commands()
                case _:
                    print("Unknown command. Type 'show-commands' for a list of commands.")



if __name__ == "__main__":
    client = RegularClient()
    client.main_prompt()
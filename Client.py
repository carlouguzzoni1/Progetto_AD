import rpyc



HOST        = "localhost"
SERVER_PORT = 18861



def display_commands():
    print("""
    Welcome to sym-DFS Project Client.
    Commands:
    login               Logins as a user
    logout              Logs out
    create-user         Creates a new user
    delete-user         Deletes a user
    exit                Exits
    show-commands       Shows commands
    """)
    # To-do:
    # - Aggiungere comandi per interagire con i file servers.


def main_prompt():
    user_is_logged  = False
    logged_username = None
    
    print("Connecting to the name server...")
    conn            = rpyc.connect(HOST, SERVER_PORT)
    print(dir(conn.root))
    # Show available commands.
    display_commands()

    while True:
        # Get user input.
        command = input(
            "({})>".format("non-auth" if user_is_logged else logged_username)
            )
        
        match command:
            case "login":
                # To-do: aggiungere chiamata alla procedura di login.
                continue
            case "logout":
                # To-do: aggiungere chiamata alla procedura di logout.
                continue
            case "create-user":
                username = input("Insert username: ")
                password = input("Insert password: ")
                result = conn.root.create_user(username, password, False)
                print(result)
                continue
            case "delete-user":
                # To-do: aggiungere chiamata alla procedura di cancellazione.
                continue
            case "exit":
                # To-do: aggiungere procedura di salvataggio e spegnimento.
                break


if __name__ == '__main__':
    main_prompt()
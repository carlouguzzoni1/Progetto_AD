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


def main_prompt():
    logged_username = None

    # Show available commands.
    display_commands()

    while True:
        # Get user input.
        command = input(
            "({})>".format("non-auth" if logged_username is None else logged_username)
            )
        
        match command:
            case "login":
                # To-do: aggiungere chiamata alla procedura di login.
                continue
            case "logout":
                # To-do: aggiungere chiamata alla procedura di logout.
                continue
            case "create-user":
                # To-do: aggiungere chiamata alla procedura di creazione.
                continue
            case "delete-user":
                # To-do: aggiungere chiamata alla procedura di cancellazione.
                continue
            case "exit":
                # To-do: aggiungere procedura di salvataggio e spegnimento.
                break


if __name__ == '__main__':
    main_prompt()
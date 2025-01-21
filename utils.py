import datetime
import hashlib
import sys
import jwt



# NOTE: tutte le utils sono raccolte in questo files, perché alcune di esse
#       vengono usate da più entità nell'architettura. Il loro numero ed il
#       volume di codice non rendono il progetto meno chiaro.



def generate_token(user_id, role, private_key):
    """
    Generates a JWT token for clients and file servers.
    Args:
        user_id (str):      The username or the server name.
        role (str):         The role of the entity.
        private_key (str):  The private key for signing.
    Returns:
        str:                The generated JWT token.
    """
    
    payload = {
        "username": user_id,
        "role":     role
    }
    token = jwt.encode(payload, private_key, algorithm="RS384")
    
    return token


def get_token_payload(token, public_key):
    """
    Gets the payload of a JWT token.
    Args:
        token (str):  The JWT token.
    Returns:
        dict:         The payload of the token.
    """
    
    try:
        payload = jwt.decode(token, public_key, algorithms=["RS384"])
    
    except jwt.InvalidTokenError as e:
        print("Error decoding JWT token:", e)
        
        return None
    
    return payload


def calculate_checksum(file_path):
    """
    Calculates the SHA256 checksum of a file.
    Args:
        file_path (str): The path to the file.
    Returns:
        str: The SHA256 checksum of the file.
    """
    
    sha256 = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    
    return sha256.hexdigest()


def truncate(value, max_length):
    """
    Truncates a string to a maximum length.
    Args:
        value (str):        The string to truncate.
        max_length (int):   The maximum length of the string.
    Returns:
        str:                The truncated string.
    """
    
    return value[:max_length] + "..." if len(value) > max_length else value


def handle_keyboard_interrupt_client(signum, frame, client):
    """
    Handles a KeyboardInterrupt exception.
    Args:
        signum (int):       The signal number.
        frame (object):     The stack frame.
        client (object):    The client object.
    """
    
    print("\nExiting due to keyboard interrupt...")
    
    client._cleanup()   # Logout + state reset + scheduler shutdown.
    
    sys.exit(0)         # Calls __del__ -> disconnection.


def handle_keyboard_interrupt_file_server(signum, frame, file_server):
    """
    Handles a KeyboardInterrupt exception.
    Args:
        signum (int):           The signal number.
        frame (object):         The stack frame.
        file_server (object):   The file server object.
    """
    
    print("\nExiting due to keyboard interrupt...")
    
    file_server._cleanup()  # Logout + scheduler shutdown.
    
    # Stop the ThreadedServer.
    try:
        if hasattr(file_server, '_server'):
            print("Stopping the threaded server...")
            file_server._server.close()
    
    except Exception as e:
        print(f"Error stopping the threaded server: {e}")
    
    sys.exit(0)             # Calls __del__ -> disconnection.


def current_timestamp():
    """
    Returns the current timestamp in the format %Y-%m-%d %H:%M:%S.
    Returns:
        str: The current timestamp in the format %Y-%m-%d %H:%M:%S.
    """
    
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
import datetime
import hashlib
import sys



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


def current_timestamp():
    """
    Returns the current timestamp in the format %Y-%m-%d %H:%M:%S.
    Returns:
        str: The current timestamp in the format %Y-%m-%d %H:%M:%S.
    """
    
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
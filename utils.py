import hashlib
import uuid



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


def generate_uuid():
    """
    Generates a UUID randomly.
    Returns:
        str: The generated UUID.
    """
    
    return str(uuid.uuid4())


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
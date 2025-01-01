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
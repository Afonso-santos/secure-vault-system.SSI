from common.commands_utils import *
from common.utils import *


def handler_add_command(client, file_path: str):
    """
    Create a command to add a file to the server.
    """
    try:
        with open(file_path, "rb") as f:
            # Read the file content
            file_content = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

    # Encrypt the file with AES
    ciphertext, key = encrypt_file(file_content)

    # Get file name from path
    file_name = os.path.basename(file_path)

    # Hash the original file
    file_hash = hash_file(file_content)

    # Encrypt the AES key with client's public key
    encrypted_key = encrypt_key(key, client.public_key)

    # Sign the file hash
    signature = sign_data(file_hash, client.private_key)

    # Encode everything to base64 for transmission
    return create_add_command(
        file_name,
        ciphertext,
        encrypted_key,
        file_hash,
        signature,
    )


def handler_details_command(file_id: str):
    """
    Create a command to get the details of a file.

    Args:
        client: The client instance.
        file_id (str): The ID of the file.

    Returns:
        Command: The command to get the file details.
    """
    return create_details_command(file_id)


def handler_read_command(file_id: str):
    """
    Create a command to read a file.

    Args:
        client: The client instance.
        file_id (str): The ID of the file.

    Returns:
        Command: The command to read the file.
    """
    return create_read_command(file_id)

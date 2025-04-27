from common.commands_utils import *
from common.utils import *

from cryptography.hazmat.primitives.serialization import load_pem_public_key


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


def handler_replace_command(client, file_id: str, file_path: str, key):
    """
    Create a command to replace a file on the server.

    Args:
        client: The client instance.
        file_id (str): The ID of the file.
        file_path (str): The path to the new file.

    Returns:
        Command: The command to replace the file.
    """
    try:
        with open(file_path, "rb") as f:
            # Read the file content
            file_content = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

    key = base64.b64decode(key)

    key = client.private_key.decrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Encrypt the file with AES
    ciphertext, key = encrypt_file(file_content, key)

    # Hash the original file
    file_hash = hash_file(file_content)

    # Encrypt the AES key with client's public key

    # Sign the file hash
    signature = sign_data(file_hash, client.private_key)

    # Encode everything to base64 for transmission
    return create_replace_command(
        file_id,
        ciphertext,
        file_hash,
        signature,
    )


def create_replace(file_id: str, file_path: str) -> Command:
    """Create a command to respond to a replace file request."""
    payload = {
        "file_id": file_id,
        "file_path": file_path,
    }
    return create_command(CMD_TYPES.REPLACE, payload)


def handler_group_create_command(group_name: str):
    """
    Create a command to create a group.
    """
    return create_group_create_command(group_name)


def handler_group_delete_command(group_id: str):
    """
    Create a command to delete a group.
    """
    return create_group_delete_command(group_id)


def create_share(
    file_id: str, user_id: str, permissions: str, file_key: str = None, client_key=None
) -> Command:
    """Create a command to share a file with a user."""
    payload = {
        "file_id": file_id,
        "user_id": user_id,
        "permissions": permissions,
        "file_key": file_key,
        "client_key": client_key,
    }
    return create_command(CMD_TYPES.SHARE, payload)


def handler_share_command(
    client,
    file_id: str,
    user_id: str,
    permissions: str,
    file_key: str,
    client_key: str = None,
):
    """
    Create a command to share a file with a user.
    """

    client_key = load_pem_public_key(client_key.encode())

    file_key = base64.b64decode(file_key)

    print(f"---file_key: {file_key}")
    print(f"---client_key: {client_key}")

    file_key = client.private_key.decrypt(
        file_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    file_key_encrypted = client_key.encrypt(
        file_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return create_share_command(file_id, user_id, permissions, file_key_encrypted)

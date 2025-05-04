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


def handler_group_add_user_command(
    client, group_id: str, user_id: str, permissions: str, dict_keys: str, key
):
    """
    Create a command to add a user to a group.
    """

    dict_keys = json_to_dict(dict_keys)

    for file_id, file_key in dict_keys.items():

        encrypted_file_key = base64.b64decode(file_key)
        # Decrypt the file key with the client's private key
        file_key_decrypt = decrypt_key(encrypted_file_key, client.private_key)

        # Encrypt the file key with the user's public key

        file_key_encrypted = encrypt_key(file_key_decrypt, key.encode())

        dict_keys[file_id] = base64.b64encode(file_key_encrypted).decode()

    dict_keys_json = dict_to_json(dict_keys)

    return create_group_add_user_command(group_id, user_id, permissions, dict_keys_json)


def handler_group_add_user_response_command(msg: str):
    """
    Create a command to respond to a group add user request.
    """
    return create_group_add_user_response_command(msg)


def handler_group_add_file_command(
    client, group_id: str, file_path: str, dict_key: dict
):
    """
    Create a command to add a file to a group.
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

    for user_id, user_key in dict_key.items():
        # Load the user's public key
        user_key = load_pem_public_key(user_key.encode())

        # Encrypt the AES key with user's public key
        encrypted_key = encrypt_key(key, user_key)

        dict_key[user_id] = base64.b64encode(encrypted_key).decode()

    dict_key_json = dict_to_json(dict_key)
    # Sign the file hash
    signature = sign_data(file_hash, client.private_key)

    return create_group_add_file_command(
        group_id, file_name, ciphertext, dict_key_json, file_hash, signature
    )


def create_group_add_file(group_id: str, file_path: str) -> Command:
    """
    Create a command to add a file to a group.
    """
    payload = {
        "group_id": group_id,
        "file_path": file_path,
    }
    return create_command(CMD_TYPES.G_ADD, payload)


def create_group_add_user(
    group_id: str, user_id: str, permissions: str, dict_key: str = None
) -> Command:
    """
    Create a command to add a user to a group.
    """
    payload = {
        "group_id": group_id,
        "user_id": user_id,
        "permissions": permissions,
        "dict_key": dict_key,
    }
    return create_command(CMD_TYPES.G_ADD_USER, payload)


def handler_group_delete_user_command(group_id: str, user_id: str):
    """
    Create a command to delete a user from a group.
    """
    return create_group_delete_user_command(group_id, user_id)

def handler_group_list_command():
    """
    Create a command to list all groups.
    """
    return create_group_list_command()

def handler_delete_command(file_id: str):
    """
    Create a command to delete a file.
    """
    return create_delete_command(file_id)


def handler_revoke_command(file_id: str, user_id: str):
    """
    Create a command to revoke a file.
    """
    return create_revoke_command(file_id, user_id)

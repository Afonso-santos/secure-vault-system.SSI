import json
import base64
from enum import Enum


class CMD_TYPES(Enum):
    """Command types for the Command class."""

    GET = "GET"
    MULTI_GET = "MULTI_GET"

    PUT = "PUT"
    ERROR = "ERROR"

    ADD = "ADD"
    LIST = "LIST"
    SHARE = "SHARE"
    DELETE = "DELETE"
    REPLACE = "REPLACE"
    DETAILS = "DETAILS"
    REVOKE = "REVOKE"
    READ = "READ"
    G_CREATE = "G_CREATE"
    G_DELETE = "G_DELETE"
    G_ADD_USER = "G_ADD_USER"
    G_DELETE_USER = "G_DELETE_USER"
    G_LIST = "G_LIST"
    G_ADD = "G_ADD"


class Command:
    """Command class to represent a command with its type and arguments."""

    def __init__(self, cmd_type: CMD_TYPES, payload=None):
        self.type = cmd_type
        self.payload = payload

    def __repr__(self):
        return f"Command(type={self.type}, payload={self.payload})"

    def to_json(self):
        return json.dumps({"type": self.type.value, "payload": self.payload})

    @staticmethod
    def from_json(json_str: str):

        data = json.loads(json_str)

        cmd_type = CMD_TYPES[data["type"]]

        payload = data.get("payload")
        return Command(cmd_type, payload)


def create_command(cmd_type: CMD_TYPES, payload) -> Command:
    """Create a command with the given type and payload."""
    command = Command(cmd_type, payload)
    return command


def create_error_command(error_message: str) -> Command:
    """Create a command to represent an error."""
    payload = {"error": error_message}
    return create_command(CMD_TYPES.ERROR, payload)


def create_add_command(
    file_name: str,
    ciphercontent: bytes,
    encrypt_key: bytes,
    file_hash: bytes,
    signature: bytes,
) -> Command:
    """Create a command to add a file to the server."""
    payload = {
        "file_name": base64.b64encode(file_name.encode()).decode(),
        "ciphercontent": base64.b64encode(ciphercontent).decode(),
        "encrypt_key": base64.b64encode(encrypt_key).decode(),
        "file_hash": base64.b64encode(file_hash).decode(),
        "signature": base64.b64encode(signature).decode(),
    }
    return create_command(CMD_TYPES.ADD, payload)


def create_add_response_command(file_id: str) -> Command:
    """Create a command to respond to an add file request."""
    payload = {"file_id": file_id}
    return create_command(CMD_TYPES.ADD, payload)


def create_details_command(file_id: str) -> Command:
    """Create a command to get the details of a file."""
    payload = {"file_id": file_id}
    return create_command(CMD_TYPES.DETAILS, payload)


def create_details_response_command(
    file_id: str,
    file_name: str,
    file_owner: str,
    listed_users: list,
    create_at: str,
    modified_at: str,
    by: str,
) -> Command:
    """Create a command to respond to a details request."""
    payload = {
        "file_id": file_id,
        "file_name": base64.b64decode(file_name.encode()).decode(),
        "file_owner": file_owner,
        "listed_users": listed_users,
        "create_at": create_at,
        "modified_at": modified_at,
        "by": by,
    }

    return create_command(CMD_TYPES.DETAILS, payload)


def create_read_command(file_id: str) -> Command:
    """Create a command to read a file."""
    payload = {"file_id": file_id}
    return create_command(CMD_TYPES.READ, payload)


def create_read_response_command(
    key: str,
    content: str,
    file_hash: str,
    signature: str,
    last_modified: str,
) -> Command:
    """Create a command to respond to a read file request."""
    payload = {
        "key": key,
        "content": content,
        "file_hash": file_hash,
        "signature": signature,
        "last_modified": last_modified,
    }
    return create_command(CMD_TYPES.READ, payload)


def create_replace_command(
    file_id: str, ciphertext: bytes, file_hash: bytes, signature: bytes
) -> Command:
    """Create a command to replace a file on the server."""
    payload = {
        "file_id": file_id,
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "file_hash": base64.b64encode(file_hash).decode(),
        "signature": base64.b64encode(signature).decode(),
    }
    return create_command(CMD_TYPES.REPLACE, payload)


def create_replace_response_command(msg: str) -> Command:
    """Create a command to respond to a replace file request."""
    payload = {"msg": msg}
    return create_command(CMD_TYPES.REPLACE, payload)


def create_group_create_command(group_name: str) -> Command:
    """Create a command to create a group."""
    payload = {"group_name": group_name}
    return create_command(CMD_TYPES.G_CREATE, payload)


def create_group_create_response_command(group_id: str) -> Command:
    """Create a command to respond to a group creation request."""
    payload = {"group_id": group_id}
    return create_command(CMD_TYPES.G_CREATE, payload)


def create_group_delete_command(group_id: str) -> Command:
    """Create a command to delete a group."""
    payload = {"group_id": group_id}
    return create_command(CMD_TYPES.G_DELETE, payload)


def create_group_delete_response_command(msg: str) -> Command:
    """Create a command to respond to a group deletion request."""
    payload = {"msg": msg}
    return create_command(CMD_TYPES.G_DELETE, payload)


def create_share_command(
    file_id: str, user_id: str, permissions: str, key=None
) -> Command:
    """Create a command to share a file with a user."""
    payload = {
        "file_id": file_id,
        "user_id": user_id,
        "permissions": permissions,
        "key": base64.b64encode(key).decode() if key else None,
    }
    return create_command(CMD_TYPES.SHARE, payload)


def create_share_response_command(msg: str) -> Command:
    """Create a command to respond to a share file request."""
    payload = {"msg": msg}
    return create_command(CMD_TYPES.SHARE, payload)


def create_group_add_user_command(
    group_id: str, user_id: str, permission: str, file_key: str = None
) -> Command:
    """Create a command to add a user to a group."""
    payload = {
        "group_id": group_id,
        "user_id": user_id,
        "permissions": permission,
        "dict_key": file_key,
    }
    return create_command(CMD_TYPES.G_ADD_USER, payload)


def create_group_add_user_response_command(msg: str) -> Command:
    """Create a command to respond to a group add user request."""
    payload = {"msg": msg}
    return create_command(CMD_TYPES.G_ADD_USER, payload)


def create_group_add_file_command(
    group_id: str,
    file_name: str,
    ciphercontent: bytes,
    dict_key: str,
    file_hash: bytes,
    signature: bytes,
) -> Command:
    """Create a command to add a file to a group."""
    payload = {
        "group_id": group_id,
        "file_name": base64.b64encode(file_name.encode()).decode(),
        "ciphercontent": base64.b64encode(ciphercontent).decode(),
        "dict_key": dict_key,
        "file_hash": base64.b64encode(file_hash).decode(),
        "signature": base64.b64encode(signature).decode(),
    }
    return create_command(CMD_TYPES.G_ADD, payload)


def create_group_add_file_response_command(file_id: str) -> Command:
    payload = {"file_id": file_id}
    return create_command(CMD_TYPES.G_ADD, payload)


def create_group_delete_user_command(group_id: str, user_id: str) -> Command:
    """Create a command to delete a user from a group."""
    payload = {
        "group_id": group_id,
        "user_id": user_id,
    }
    return create_command(CMD_TYPES.G_DELETE_USER, payload)

def create_group_list_command() -> Command:
    """Create a command to list the files in a group."""
    payload = {}
    return create_command(CMD_TYPES.G_LIST, payload)

def create_group_list_response_command(dict_groups: str) -> Command:
    """Create a command to respond to a group list request."""
    payload = {
        "dict_groups": dict_groups,
    }
    return create_command(CMD_TYPES.G_LIST, payload)

def create_delete_command(file_id: str) -> Command:
    """Create a command to delete a file."""
    payload = {"file_id": file_id}
    return create_command(CMD_TYPES.DELETE, payload)


def create_delete_response_command(msg: str) -> Command:
    """Create a command to respond to a delete file request."""
    payload = {"msg": msg}
    return create_command(CMD_TYPES.DELETE, payload)


def create_revoke_command(file_id: str, user_id: str) -> Command:
    """Create a command to revoke a file from a user."""
    payload = {
        "file_id": file_id,
        "user_id": user_id,
    }
    return create_command(CMD_TYPES.REVOKE, payload)


def create_revoke_response_command(msg: str) -> Command:
    """Create a command to respond to a revoke file request."""
    payload = {"msg": msg}
    return create_command(CMD_TYPES.REVOKE, payload)


def create_list_command(flag:str ,id_thing: str) -> Command:
    """Create a command to list all files."""
    payload = {
        "flag": flag,
        "id_thing": id_thing
    }
    return create_command(CMD_TYPES.LIST, payload)
    
def create_list_response_command(dict_files: str) -> Command:
    """Create a command to respond to a list files request."""
    payload = {
        "dict_files": dict_files,
    }
    return create_command(CMD_TYPES.LIST, payload)
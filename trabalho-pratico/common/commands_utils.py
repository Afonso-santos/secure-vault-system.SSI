import json
import base64
from enum import Enum


class CMD_TYPES(Enum):
    """Command types for the Command class."""

    GET = "GET"
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
    G_CREATE = "GROUP_CREATE"
    G_DELETE = "GROUP_DELETE"
    G_ADD_USER = "GROUP_ADD_USER"
    G_DELETE_USER = "GROUP_DELETE_USER"
    G_LIST = "GROUP_LIST"
    G_ADD = "GROUP_ADD"


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
) -> Command:
    """Create a command to respond to a read file request."""
    payload = {
        "key": key,
        "content": content,
        "file_hash": file_hash,
        "signature": signature,
    }
    return create_command(CMD_TYPES.READ, payload)

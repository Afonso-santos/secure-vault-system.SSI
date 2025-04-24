import os
import json
import uuid
import shutil
import base64
from enum import Enum
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from abc import ABC, abstractmethod
import hashlib

from common.commands_utils import (
    CMD_TYPES,
    Command,
    create_add_response_command,
    create_details_response_command,
    create_error_command,
    create_read_response_command,
)
from common.utils import dict_to_json, json_to_dict

PATH = "server/storage/"


class Permission(Enum):
    READ = "read"
    WRITE = "write"


class User:
    def __init__(self, user_id: str, name: str, vault_path: str):
        self.user_id = user_id
        self.name = name
        self.vault_path = None
        self.groups: List[str] = []


class Group:
    def __init__(self, group_id: str, owner_id: str):
        self.group_id = group_id
        self.owner_id = owner_id
        self.members: List[str] = []
        # Dictionary mapping member_id to their permissions in this group
        self.member_permissions: Dict[str, Set[Permission]] = {}
        self.created_at = datetime.now()
        self.modified_at = datetime.now()

    def add_member(self, user_id: str, permissions: Set[Permission] = None):
        if user_id not in self.members:
            self.members.append(user_id)
            self.member_permissions[user_id] = permissions or set()
            self.modified_at = datetime.now()

    def remove_member(self, user_id: str):
        if user_id in self.members:
            self.members.remove(user_id)
            if user_id in self.member_permissions:
                del self.member_permissions[user_id]
            self.modified_at = datetime.now()

    def set_member_permissions(self, user_id: str, permissions: Set[Permission]):
        if user_id in self.members:
            self.member_permissions[user_id] = permissions
            self.modified_at = datetime.now()
            return True
        return False

    def get_member_permissions(self, user_id: str) -> Set[Permission]:
        return self.member_permissions.get(user_id, set())


class File:
    def __init__(
        self,
        file_id: str,
        file_name: str,
        owner_id: str,
        last_changed: str,
    ):
        self.file_id = file_id
        self.file_name = file_name
        self.owner_id = owner_id
        self.path = None
        self.last_changed = last_changed
        self.listed_users: dict[str, str] = {}  # user_id -> key
        self.created_at = datetime.now()
        self.modified_at = datetime.now()

        # self.listed_users.append(owner_id)

    def set_path(self, path: str = None):
        self.path = path

    def add_user(self, user_id: str, key: str):
        if user_id not in self.listed_users:
            self.listed_users[user_id] = key


class AccessControl:
    def __init__(self):
        # Direct permissions: user_id -> {file_id -> {permissions}}
        self.permissions: Dict[str, Dict[str, Set[Permission]]] = {}

    def add_permission(self, user_id: str, file_id: str, permission: Permission):
        if user_id not in self.permissions:
            self.permissions[user_id] = {}
        if file_id not in self.permissions[user_id]:
            self.permissions[user_id][file_id] = set()
        self.permissions[user_id][file_id].add(permission)

    def remove_permission(self, user_id: str, file_id: str, permission: Permission):
        if user_id in self.permissions and file_id in self.permissions[user_id]:
            self.permissions[user_id][file_id].discard(permission)
            if not self.permissions[user_id][file_id]:
                del self.permissions[user_id][file_id]
                if not self.permissions[user_id]:
                    del self.permissions[user_id]

    def check_permission(
        self, user_id: str, file_id: str, permission: Permission
    ) -> bool:
        return (
            user_id in self.permissions
            and file_id in self.permissions[user_id]
            and permission in self.permissions[user_id][file_id]
        )

    def get_permissions(self, user_id: str, file_id: str) -> Set[Permission]:
        return self.permissions.get(user_id, {}).get(file_id, set())


class FileSystem:
    def __init__(self):
        # user_id -> User
        self.users: dict[str, User] = {}
        # group_id -> Group
        self.groups: dict[str, Group] = {}
        # file_id -> File
        self.files: dict[str, File] = {}
        self.acess_control = AccessControl()

    def proccess_cmd(self, decrypt_data, client_id):
        """
        Process the command given by the user
        Returns a dict with command results for the client to handle
        """
        print(f"Processing command: {decrypt_data}")

        # Parse the data if it's a string
        if isinstance(decrypt_data, str):
            try:
                data = json.loads(decrypt_data)
            except json.JSONDecodeError as e:
                print(f"Error parsing command JSON: {e}")
                return {"error": "Invalid command format"}
        else:
            data = decrypt_data

        cmd_type = CMD_TYPES(data["type"])
        cmd = Command(cmd_type, data.get("payload", {}))

        print(f"Command type: {cmd.type}")
        print(f"Command payload: {cmd.payload}")

        try:
            match cmd_type:
                case CMD_TYPES.ADD:
                    print("Adding file")
                    return self.add_file(
                        cmd.payload,
                        client_id,
                    )

                case CMD_TYPES.DETAILS:
                    print("Getting file details")
                    return self.file_details(cmd.payload, client_id)

                case CMD_TYPES.READ:
                    print("Reading file")
                    return self.read_file(cmd.payload, client_id)

                # case CMD_TYPES.LIST:
                #     return self.list_files(client_id)
                # case CMD_TYPES.SHARE:
                #     return self.share_file(decrypt_data.payload, client_id)
                # case CMD_TYPES.DELETE:
                #     return self.delete_file(decrypt_data.payload, client_id)
                # case CMD_TYPES.REPLACE:
                #     return self.replace_file(decrypt_data.payload, client_id)
                # case CMD_TYPES.DETAILS:
                #     return self.file_details(decrypt_data.payload, client_id)
                # case CMD_TYPES.REVOKE:
                #     return self.revoke_file_access(decrypt_data.payload, client_id)
                # case CMD_TYPES.G_CREATE:
                #     return self.create_group(decrypt_data.payload, client_id)
                # case CMD_TYPES.G_DELETE:
                #     return self.delete_group(decrypt_data.payload, client_id)
                # case CMD_TYPES.G_ADD_USER:
                #     return self.add_user_to_group(decrypt_data.payload, client_id)
                # case CMD_TYPES.G_DELETE_USER:
                #     return self.remove_user_from_group(decrypt_data.payload, client_id)
                # case CMD_TYPES.G_LIST:
                #     return self.list_groups(client_id)
                # case CMD_TYPES.G_ADD:
                #     return self.add_file_to_group(decrypt_data.payload, client_id)
                # case CMD_TYPES.READ:
                #     return self.read_file(decrypt_data.payload, client_id)
                case _:
                    raise ValueError("Unknown command type")
        except Exception as e:
            print(f"Error processing command: {e}")
            return {"error": str(e)}

    def add_file(self, payload, client_id: str) -> str:
        """
        Add a file to the file system with proper key management.
        """
        file_id = "file_" + str(len(self.files) + 1)
        file_name = payload["file_name"]
        ciphercontent = payload["ciphercontent"]  # Base64 encoded encrypted content
        encrypt_key = payload["encrypt_key"]  # RSA-encrypted AES key
        file_hash = payload["file_hash"]  # Hash of original file
        signature = payload["signature"]  # Signature of file hash

        # Create file object
        file = File(
            file_id=file_id,
            file_name=file_name,
            owner_id=client_id,
            last_changed=client_id,
        )

        file.add_user(client_id, encrypt_key)
        path_file = os.path.join(PATH, client_id, file_name)
        file.set_path(path_file)

        # Create or update user
        user = User(
            user_id=client_id,
            name=client_id,
            vault_path=os.path.join(PATH, client_id),
        )

        self.users[client_id] = user
        # Add the file to the file system
        self.files[file_id] = file
        self.acess_control.add_permission(client_id, file_id, Permission.READ)
        self.acess_control.add_permission(client_id, file_id, Permission.WRITE)

        file_data = (
            str(len(ciphercontent))
            + ciphercontent
            + str(len(file_hash))
            + file_hash
            + str(len(signature))
            + signature
        )

        try:
            os.makedirs(os.path.dirname(path_file), exist_ok=True)
            with open(path_file, "w") as f:
                f.write(file_data)
        except Exception as e:
            return create_error_command(f"Error writing file: {str(e)}").to_json()

        return create_add_response_command(file_id).to_json()

    def file_details(self, payload, client_id: str) -> dict:
        """
        Get file details.
        """
        file_id = payload["file_id"]

        if file_id not in self.files:
            return {"error": "File not found"}

        file = self.files[file_id]

        # Check if client has read permission
        if not self.acess_control.check_permission(client_id, file_id, Permission.READ):
            return create_error_command("Permission denied").to_json()

        return create_details_response_command(
            file_id,
            file.file_name,
            file.owner_id,
            list(file.listed_users.keys()),
            file.created_at.isoformat(),
            file.modified_at.isoformat(),
            file.last_changed,
        ).to_json()

    def read_file(self, payload, client_id: str) -> dict:
        """
        Read a file and provide the client with their specific decryption key.
        """
        file_id = payload["file_id"]

        if file_id not in self.files:
            return create_error_command("File not found").to_json()

        file = self.files[file_id]

        # Check if client has read permission
        if not self.acess_control.check_permission(client_id, file_id, Permission.READ):
            return create_error_command("Permission denied").to_json()

        file_path = file.path
        key = file.listed_users.get(client_id)

        try:
            with open(file_path, "r") as f:
                file_data = f.read()

            i = 0
            # Read length of ciphercontent (assume max 5 digits for simplicity)
            while file_data[i].isdigit():
                i += 1
            len_cipher = int(file_data[:i])
            ciphercontent = file_data[i : i + len_cipher]
            i += len_cipher

            # Read length of file_hash
            j = i
            while file_data[j].isdigit():
                j += 1
            len_hash = int(file_data[i:j])
            file_hash = file_data[j : j + len_hash]
            j += len_hash

            # Read length of signature
            k = j
            while file_data[k].isdigit():
                k += 1
            len_signature = int(file_data[j:k])
            signature = file_data[k : k + len_signature]

            print(f"ciphercontent: {ciphercontent}")
            print(f"file_hash: {file_hash}")
            print(f"signature: {signature}")

            # Return the file data and encryption key to the client
            return create_read_response_command(
                key,
                ciphercontent,
                file_hash,
                signature,
            ).to_json()
        except Exception as e:
            return create_error_command(f"Error reading file: {str(e)}").to_json()

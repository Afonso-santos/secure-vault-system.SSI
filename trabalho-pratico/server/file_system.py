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
    create_replace_response_command,
    create_details_response_command,
    create_group_create_response_command,
    create_group_delete_response_command,
    create_share_response_command,
)

from common.utils import dict_to_json, json_to_dict

PATH = "server/storage/"


class Permission(Enum):
    OWN = "own"
    READ = "read"
    WRITE = "write"


class User:
    def __init__(self, user_id: str, name: str, vault_path: str):
        self.user_id = user_id
        self.name = name
        self.vault_path = vault_path
        self.list_of_files: List[str] = []
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
        self.created_at = str(datetime.now())
        self.modified_at = str(datetime.now())

        # self.listed_users.append(owner_id)

    def set_path(self, path: str = None):
        self.path = path

    def add_user(self, user_id: str, key: str):
        if user_id not in self.listed_users:
            self.listed_users[user_id] = key

    def set_modified_at(self, modified_at: str, last_changed: str):
        self.modified_at = modified_at
        self.last_changed = last_changed


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

    def add_user(self, user_id: str, name: str):
        """
        Add a user to the file system.
        """
        if user_id not in self.users:
            self.users[user_id] = User(user_id, name, os.path.join(PATH, user_id))
            os.makedirs(self.users[user_id].vault_path, exist_ok=True)
            print(f"User {user_id} added to the file system.")
        else:
            print(f"User {user_id} already exists in the file system.")

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

                case CMD_TYPES.REPLACE:
                    print("Replacing file")
                    return self.replace(cmd.payload, client_id)

                case CMD_TYPES.G_CREATE:
                    print("Creating group")
                    return self.create_group(cmd.payload, client_id)

                case CMD_TYPES.G_DELETE:
                    print("Deleting group")
                    return self.delete_group(cmd.payload, client_id)

                case CMD_TYPES.SHARE:
                    print("Sharing file")
                    return self.share_file(cmd.payload, client_id)

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

    def get_thing(self, thing_id: str, client_id) -> Optional[User | Group | File]:
        """
        Get a user, group, or file by ID.
        """
        if thing_id in self.users:
            return self.users[thing_id]
        elif thing_id in self.groups:
            return self.groups[thing_id]
        elif thing_id in self.files:
            file = self.files[thing_id]
            key = file.listed_users.get(client_id)
            return key
        else:
            return None

    def add_file(self, payload, client_id: str) -> str:
        """
        Add a file to the file system with proper key management.
        """
        print("Adding file numver: ", len(self.files))
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
        self.files[file_id] = file

        file.add_user(client_id, encrypt_key)

        path_file = os.path.join(PATH, client_id, file_name)
        file.set_path(path_file)

        # Add the file to the file system
        self.files[file_id] = file
        self.users[client_id].list_of_files.append(file_id)
        self.acess_control.add_permission(client_id, file_id, Permission.OWN)
        self.acess_control.add_permission(client_id, file_id, Permission.READ)
        self.acess_control.add_permission(client_id, file_id, Permission.WRITE)

        file_data = ciphercontent + " " + file_hash + " " + signature

        if -1 == write_file(file.path, file_data):
            return create_error_command("Error writing file").to_json()

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
            file.created_at,
            file.modified_at,
            file.last_changed,
        ).to_json()

    def replace(self, payload, client_id: str) -> dict:
        """
        Replace a file in the file system.
        """
        print("payload: ", payload)
        file_id = payload["file_id"]

        if file_id not in self.files:
            return create_error_command("File not found").to_json()

        if not self.acess_control.check_permission(
            client_id, file_id, Permission.WRITE
        ):
            return create_error_command("Permission denied").to_json()

        file = self.files[file_id]
        ciphertext = payload["ciphertext"]
        file_hash = payload["file_hash"]
        signature = payload["signature"]

        file.set_modified_at(datetime.now().isoformat(), client_id)
        self.files[file_id] = file

        file_data = ciphertext + " " + file_hash + " " + signature

        if -1 == write_file(file.path, file_data):
            return create_error_command("Error writing file").to_json()

        return create_replace_response_command(
            f"File {file_id} replaced successfully"
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

            # Split file data by spaces
            parts = file_data.split(" ")  # Split into 3 parts at most
            if len(parts) != 3:
                return create_error_command("Invalid file format").to_json()

            ciphercontent = parts[0]
            file_hash = parts[1]
            signature = parts[2]

            print(f"ciphercontent: {ciphercontent}")
            print(f"file_hash: {file_hash}")
            print(f"signature: {signature}")

            # Return the file data and encryption key to the client
            return create_read_response_command(
                key,
                ciphercontent,
                file_hash,
                signature,
                file.last_changed,
            ).to_json()
        except Exception as e:
            return create_error_command(f"Error reading file: {str(e)}").to_json()

    def create_group(self, payload, client_id: str) -> dict:
        """
        Create a group and add the user to it.
        """
        group_id = "group_" + str(len(self.groups) + 1)

        group = Group(group_id, client_id)
        group.add_member(client_id, {Permission.OWN, Permission.READ, Permission.WRITE})

        self.groups[group_id] = group

        user = self.users[client_id]

        user.groups.append(group_id)

        self.users[client_id].groups.append(group_id)

        return create_group_create_response_command(group_id).to_json()

    def delete_group(self, payload, client_id: str) -> dict:
        """
        Delete a group and remove the user from it.
        """
        group_id = payload["group_id"]

        if group_id not in self.groups:
            return create_error_command("Group not found").to_json()

        group = self.groups[group_id]

        # Check if client is the owner of the group
        if group.owner_id != client_id:
            return create_error_command("Permission denied").to_json()

        # Remove the group from the user's groups
        for user in self.users.values():
            if group_id in user.groups:
                user.groups.remove(group_id)

        # Delete the group
        del self.groups[group_id]
        self.acess_control.permissions.pop(group_id, None)

        return create_group_delete_response_command(
            f"Group {group_id} deleted successfully"
        ).to_json()

    def share_file(self, payload, client_id: str) -> dict:
        """
        Share a file with another user.
        """
        file_id = payload["file_id"]
        user_id = payload["user_id"]
        permissions = payload["permissions"]
        file_key = payload["key"]

        if file_id not in self.files:
            return create_error_command("File not found").to_json()

        # if user_id not in self.users:
        #     return create_error_command("User not found").to_json()

        if file_id in self.files:

            file = self.files[file_id]

            file.add_user(user_id, file_key)

            # Set permissions for the user
            self.acess_control.add_permission(user_id, file_id, Permission(permissions))

            return create_share_response_command(
                f"File {file_id} shared with {user_id} successfully"
            ).to_json()


def write_file(file_path: str, data: str) -> None:
    """
    Write data to a file.
    """
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w") as f:
            f.write(data)
    except Exception as e:
        return -1

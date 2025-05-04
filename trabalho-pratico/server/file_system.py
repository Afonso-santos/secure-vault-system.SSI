import os
import json
from enum import Enum
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from abc import ABC, abstractmethod
import hashlib
from common.Icarus_Protocol import create_multi_get
from common.commands_utils import (
    CMD_TYPES,
    Command,
    create_add_response_command,
    create_delete_response_command,
    create_details_response_command,
    create_error_command,
    create_read_response_command,
    create_replace_response_command,
    create_details_response_command,
    create_group_create_response_command,
    create_group_delete_response_command,
    create_revoke_response_command,
    create_share_response_command,
    create_group_add_user_response_command,
    create_group_add_file_response_command,
    create_group_list_response_command,
    create_list_response_command
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

    def add_file(self, file_id: str):
        if file_id not in self.list_of_files:
            self.list_of_files.append(file_id)

    def remove_file(self, file_id: str):
        if file_id in self.list_of_files:
            self.list_of_files.remove(file_id)
            return True
        return False

    def add_group(self, group_id: str):
        if group_id not in self.groups:
            self.groups.append(group_id)

    def remove_group(self, group_id: str):
        if group_id in self.groups:
            self.groups.remove(group_id)
            return True
        return False


class Group:
    def __init__(self, group_id: str, owner_id: str, group_name: str = None):
        self.group_id = group_id
        self.group_name = group_name
        self.owner_id = owner_id
        self.vault_path = None
        self.members: List[str] = []
        self.list_of_files: List[str] = []

        # Dictionary mapping member_id to their permissions in this group
        self.member_permissions: Dict[str, Set[Permission]] = {}

    def add_member(self, user_id: str, permissions: Set[Permission] = None):
        if user_id not in self.members:
            self.members.append(user_id)
            self.member_permissions[user_id] = permissions or set()

    def add_file(self, file_id: str):
        if file_id not in self.list_of_files:
            self.list_of_files.append(file_id)

    def remove_member(self, user_id: str):
        if user_id in self.members:
            self.members.remove(user_id)
            if user_id in self.member_permissions:
                del self.member_permissions[user_id]

    def set_member_permissions(self, user_id: str, permissions: Set[Permission]):
        if user_id in self.members:
            self.member_permissions[user_id] = permissions
            return True
        return False

    def get_member_permissions(self, user_id: str) -> Set[Permission]:
        return self.member_permissions.get(user_id, set())

    def check_permission(self, user_id: str, permission: Permission) -> bool:
        return user_id in self.members and permission in self.member_permissions.get(
            user_id, set()
        )


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

    def remove_user(self, user_id: str):
        if user_id in self.listed_users:
            del self.listed_users[user_id]
            return True
        return False


class AccessControl:
    def __init__(self):
        # Direct permissions: user_id -> {file_id -> {permissions}}
        self.permissions: Dict[str, Dict[str, Set[Permission]]] = {}
        # Group permissions: group_id -> {user_id {file_id -> {permissions}}}
        self.group_acl: Dict[str, Dict[str, Dict[str, Set[Permission]]]] = {}

    def create_group_acl(self, group_id: str):
        if group_id not in self.group_acl:
            self.group_acl[group_id] = {}

    def add_group_permission(
        self, group_id: str, user_id: str, file_id: str, permission: Set[Permission]
    ):
        if group_id not in self.group_acl:
            self.group_acl[group_id] = {}
        if user_id not in self.group_acl[group_id]:
            self.group_acl[group_id][user_id] = {}
        if file_id not in self.group_acl[group_id][user_id]:
            self.group_acl[group_id][user_id][file_id] = set()
        self.group_acl[group_id][user_id][file_id].update(permission)

    def add_permission(self, user_id: str, file_id: str, permissions: Set[Permission]):
        if user_id not in self.permissions:
            self.permissions[user_id] = {}
        if file_id not in self.permissions[user_id]:
            self.permissions[user_id][file_id] = set()
        self.permissions[user_id][file_id].update(permissions)

    def remove_permission(self, user_id: str, file_id: str, permission: Permission):
        if user_id in self.permissions and file_id in self.permissions[user_id]:
            self.permissions[user_id][file_id].discard(permission)
            if not self.permissions[user_id][file_id]:
                del self.permissions[user_id][file_id]
                if not self.permissions[user_id]:
                    del self.permissions[user_id]

    def remove_group_permission(
        self, group_id: str, user_id: str, file_id: str, permission: Permission
    ):
        if group_id in self.group_acl and user_id in self.group_acl[group_id]:
            if file_id in self.group_acl[group_id][user_id]:
                self.group_acl[group_id][user_id][file_id].discard(permission)
                if not self.group_acl[group_id][user_id][file_id]:
                    del self.group_acl[group_id][user_id][file_id]
                    if not self.group_acl[group_id][user_id]:
                        del self.group_acl[group_id][user_id]
                        if not self.group_acl[group_id]:
                            del self.group_acl[group_id]

    def check_permission(
        self, user_id: str, file_id: str, permission: Permission
    ) -> bool:
        return (
            user_id in self.permissions
            and file_id in self.permissions[user_id]
            and permission in self.permissions[user_id][file_id]
        )

    def check_group_permission(
        self, group_id: str, user_id: str, file_id: str, permission: Permission
    ) -> bool:
        return (
            group_id in self.group_acl
            and user_id in self.group_acl[group_id]
            and file_id in self.group_acl[group_id][user_id]
            and permission in self.group_acl[group_id][user_id][file_id]
        )

    def get_permissions(self, user_id: str, file_id: str) -> Set[Permission]:
        return self.permissions.get(user_id, {}).get(file_id, set())

    def has_permission(self, user_id: str, file_id: str, permission: str) -> bool:

        if user_id in self.permissions:
            if file_id in self.permissions[user_id]:
                if permission in self.permissions[user_id][file_id]:
                    return True

        for group_id, user_permissions in self.group_acl.items():
            if user_id in user_permissions:
                if file_id in user_permissions[user_id]:
                    if permission in user_permissions[user_id][file_id]:
                        return True
        return False


class FileSystem:
    def __init__(self):
        # user_id -> User
        self.count_users = 1
        self.users: dict[str, User] = {}
        # group_id -> Group
        self.count_groups = 1
        self.groups: dict[str, Group] = {}
        # file_id -> File
        self.count_files = 1
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

                case CMD_TYPES.REVOKE:
                    print("Revoking file access")
                    return self.revoke_user(cmd.payload, client_id)

                case CMD_TYPES.SHARE:
                    print("Sharing file")
                    return self.share_file(cmd.payload, client_id)
                case CMD_TYPES.G_ADD_USER:
                    return self.add_user_to_group(cmd.payload, client_id)
                
                case CMD_TYPES.G_LIST:
                    print("Listing group")
                    return self.list_groups(cmd.payload, client_id)

                case CMD_TYPES.G_ADD:

                    if cmd.payload["dict_key"] is None:

                        group_id = cmd.payload["group_id"]

                        if group_id not in self.groups:
                            return create_error_command("Group not found").to_json()

                        group = self.groups.get(group_id)

                        members_dict = {member: None for member in group.members}

                        members_dict_json = dict_to_json(members_dict)

                        return create_multi_get(
                            members_dict_json,
                            cmd.to_json(),
                        ).to_json()

                    else:
                        return self.add_file_to_group(cmd.payload, client_id)
                case CMD_TYPES.G_DELETE_USER:
                    return self.remove_user_from_group(cmd.payload, client_id)
                case CMD_TYPES.DELETE:
                    print("Deleting file")
                    return self.delete_file(cmd.payload, client_id)

                case CMD_TYPES.LIST:
                    print("Listing files")
                    return self.list_files(cmd.payload, client_id)
                case _:
                    raise ValueError("Unknown command type")
        except Exception as e:
            print(f"Error processing command: {e}")
            return {"error": str(e)}

    def get_thing(self, thing_id: str, client_id=None) -> Optional[User | Group | File]:
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
        print("Adding file number: ", len(self.files))
        file_id = "file_"+ str(self.count_files)
        self.count_files += 1
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

        self.acess_control.add_permission(
            client_id, file_id, {Permission.OWN, Permission.READ, Permission.WRITE}
        )

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

        # Check if client has read permission (either directly or through a group)
        has_permission = self.acess_control.has_permission(client_id, file_id, Permission.READ)
        if not has_permission:
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


        has_permission = self.acess_control.has_permission(
            client_id, file_id, Permission.WRITE
        )
        if not has_permission:
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
        user = self.users.get(client_id)

        # Check if client has read permission
        print(f"self.acess_control.permissions: {self.acess_control.permissions}")
        for user_id, file_permissions in self.acess_control.permissions.items():
            print(f"user_id: {user_id}")
            print(f"file_permissions: {file_permissions}")
            for file_id, permissions in file_permissions.items():
                print(f"file_id: {file_id}")
                if file_id in file_permissions:
                    print(f"file_permissions[file_id]: {file_permissions[file_id]}")
                    if Permission.READ in file_permissions[file_id]:
                        print(f"Permission granted to {user_id} for {file_id}")

        print("....................................................................")
        print(f"self.acess_control.group_acl: {self.acess_control.group_acl}")
        for group_id, user_permissions in self.acess_control.group_acl.items():
            print(f"group_id: {group_id}")
            print(f"user_permissions: {user_permissions}")
            for user_id, file_permissions in user_permissions.items():
                print(f"user_id: {user_id}")
                for file_id, permissions in file_permissions.items():
                    print(f"file_id: {file_id}")
                    if file_id in file_permissions:
                        print(f"file_permissions[file_id]: {file_permissions[file_id]}")
                        if Permission.READ in file_permissions[file_id]:
                            print(f"Permission granted to {user_id} for {file_id}")
        print("....................................................................")

        if not self.acess_control.has_permission(client_id, file_id, Permission.READ):
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
        group_id = "group_" + str(self.count_groups)
        self.count_groups += 1
        group_name = payload["group_name"]

        group = Group(group_id, client_id, group_name)
        group.vault_path = os.path.join(PATH, group_name)
        group.add_member(client_id, {Permission.OWN, Permission.READ, Permission.WRITE})

        self.groups[group_id] = group

        self.users[client_id].groups.append(group_id)
        self.acess_control.create_group_acl(group_id)

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

        file = self.files[file_id]

        file.add_user(user_id, file_key)

        # Set permissions for the user
        print(f"Adding user {user_id} to file {file_id} with permission {permissions}")
        self.acess_control.add_permission(user_id, file_id, {Permission(permissions)})

        return create_share_response_command(
            f"File {file_id} shared with {user_id} successfully"
        ).to_json()

    def add_user_to_group(self, payload, client_id: str) -> dict:
        """
        Add a user to a group.
        """

        group_id = payload["group_id"]
        user_id = payload["user_id"]
        permission = payload["permissions"]

        file_key = payload["dict_key"]  # RSA-encrypted AES key
        file_key = json_to_dict(file_key) if file_key else {}

        if group_id not in self.groups:
            return create_error_command("Group not found").to_json()

        group = self.groups[group_id]

        # Check if client is the owner of the group
        if group.owner_id != client_id:
            return create_error_command("Permission denied").to_json()

        # Add the user to the group
        group.add_member(user_id, {Permission(permission)})

        print(f"Adding user {user_id} to group {group_id} with permission {permission}")
        file_id = None
        for file_id, file_key in file_key.items():
            file = self.files[file_id]
            file.add_user(user_id, file_key)

        # Set permissions for the user
        self.acess_control.add_group_permission(
            group_id, user_id, file_id, {Permission(permission)}
        )

        return create_group_add_user_response_command(
            f"User {user_id} with {permission} added to group {group_id} successfully"
        ).to_json()

    def add_file_to_group(self, payload, client_id: str) -> dict:
        """
        Add a file to a group.
        """

        group_id = payload["group_id"]
        file_id = "file_" + str(self.count_files)
        self.count_files += 1
        file_name = payload["file_name"]
        ciphercontent = payload["ciphercontent"]  # Base64 encoded encrypted content
        encrypt_key = payload["dict_key"]  # RSA-encrypted AES key
        file_hash = payload["file_hash"]  # Hash of original file
        signature = payload["signature"]  # Signature of file hash

        if group_id not in self.groups:
            return create_error_command("Group not found").to_json()

        group = self.groups.get(group_id)

        if not group.check_permission(client_id, Permission.WRITE):
            return create_error_command("Permission denied").to_json()

        file = File(
            file_id=file_id,
            file_name=file_name,
            owner_id=client_id,
            last_changed=client_id,
        )
        self.files[file_id] = file

        encrypt_key = json_to_dict(encrypt_key)
        for user_id, key in encrypt_key.items():
            if file.listed_users is not user_id:
                file.add_user(user_id, key)

        path_file = os.path.join(group.vault_path, file_name)
        file.set_path(path_file)

        self.files[file_id] = file
        self.groups[group_id].list_of_files.append(file_id)

        for user_id, permissons in group.member_permissions.items():
            self.acess_control.add_group_permission(
                group_id, user_id, file_id, permissons
            )

        file_data = ciphercontent + " " + file_hash + " " + signature
        if -1 == write_file(file.path, file_data):
            return create_error_command("Error writing file").to_json()

        return create_group_add_file_response_command(
            f"File {file_id} added to group {group_id} successfully"
        ).to_json()

    def remove_user_from_group(self, payload, client_id: str) -> dict:
        """
        Remove a user from a group.
        """
        group_id = payload["group_id"]
        user_id = payload["user_id"]

        if group_id not in self.groups:
            return create_error_command("Group not found").to_json()

        group = self.groups.get(group_id)

        # Check if client is the owner of the group
        if group.owner_id != client_id:
            return create_error_command("Permission denied").to_json()

        # Remove the user from the group
        group.remove_member(user_id)

        # Remove the user's permissions for all files in the group
        for file_id in group.list_of_files:
            self.acess_control.remove_group_permission(
                group_id, user_id, file_id, Permission.READ
            )
            self.files[file_id].remove_user(user_id)

        return create_group_delete_response_command(
            f"User {user_id} removed from group {group_id} successfully"
        ).to_json()

    def list_groups(self, payload, client_id: str) -> dict:
            """
            List all groups the user is a member of, including their permissions for each group.
            """
            user = self.users.get(client_id)
            if not user:
                return create_error_command("User not found").to_json()

            groups_dict = {}
            for group_id, group in self.groups.items():
                if client_id in group.members:
                    # Get user's permissions for this group
                    permissions = [p.value for p in group.get_member_permissions(client_id)]
                    is_owner = group.owner_id == client_id

                    groups_dict[group_id] = {
                        "group_name": group.group_name,
                        "permissions": permissions,
                        "is_owner": is_owner
                    }

            groups_dict= dict_to_json(groups_dict)

            return create_group_list_response_command(groups_dict).to_json()
    def delete_file(self, payload, client_id: str) -> dict:
        """
        Delete a file from the file system.
        Three cases:
        1. User's personal file - completely removed from system
        2. Group file where user is owner/creator - completely removed from system
        3. Shared file - user loses access but file remains in system
        """
        file_id = payload["file_id"]

        if file_id not in self.files:
            return create_error_command("File not found").to_json()

        file = self.files[file_id]

        # Check if it's a personal file (user is the owner)
        if file.owner_id == client_id:
            # Delete the file entirely
            try:
                if os.path.exists(file.path):
                    os.remove(file.path)

                # Remove file from all users' lists
                for user in self.users.values():
                    user.remove_file(file_id)

                # Remove all permissions for this file
                for user_id in list(self.acess_control.permissions.keys()):
                    if (
                        user_id in self.acess_control.permissions
                        and file_id in self.acess_control.permissions[user_id]
                    ):
                        self.acess_control.permissions[user_id].pop(file_id, None)

                # Remove from groups if it's part of any
                for group in self.groups.values():
                    if file_id in group.list_of_files:
                        group.list_of_files.remove(file_id)

                # Remove file from system
                del self.files[file_id]
                return create_delete_response_command(
                    f"File {file_id} deleted successfully"
                ).to_json()

            except Exception as e:
                return create_error_command(f"Error deleting file: {str(e)}").to_json()

        # Check if file belongs to a group where user is owner/creator
        for group_id, group in self.groups.items():
            if file_id in group.list_of_files and group.owner_id == client_id:
                # Delete the file entirely
                try:
                    if os.path.exists(file.path):
                        os.remove(file.path)

                    group.list_of_files.remove(file_id)

                    # Remove file from all users' lists and permissions
                    for user in self.users.values():
                        user.remove_file(file_id)

                    # Remove group permissions for this file
                    for g_id in list(self.acess_control.group_acl.keys()):
                        for u_id in list(
                            self.acess_control.group_acl.get(g_id, {}).keys()
                        ):
                            if file_id in self.acess_control.group_acl.get(
                                g_id, {}
                            ).get(u_id, {}):
                                self.acess_control.group_acl[g_id][u_id].pop(
                                    file_id, None
                                )

                    # Remove individual permissions for this file
                    for user_id in list(self.acess_control.permissions.keys()):
                        if (
                            user_id in self.acess_control.permissions
                            and file_id in self.acess_control.permissions[user_id]
                        ):
                            self.acess_control.permissions[user_id].pop(file_id, None)

                    # Remove file from system
                    del self.files[file_id]
                    return create_delete_response_command(
                        f"File {file_id} deleted from group {group_id} successfully"
                    ).to_json()
                except Exception as e:
                    return create_error_command(
                        f"Error deleting file: {str(e)}"
                    ).to_json()

        # If we get here, user is not the owner, so just remove their access
        if self.acess_control.has_permission(client_id, file_id, Permission.READ):
            # Remove user's access to the file
            self.acess_control.remove_permission(client_id, file_id, Permission.READ)
            self.acess_control.remove_permission(client_id, file_id, Permission.WRITE)
            self.acess_control.remove_permission(client_id, file_id, Permission.OWN)

            # Remove user's access from group permissions if applicable
            for group_id in list(self.acess_control.group_acl.keys()):
                if client_id in self.acess_control.group_acl.get(group_id, {}):
                    if file_id in self.acess_control.group_acl[group_id][client_id]:
                        self.acess_control.group_acl[group_id][client_id].pop(
                            file_id, None
                        )

            # Remove file key from user's listed_users in the File
            file.remove_user(client_id)

            # Remove from user's list of files
            if client_id in self.users:
                self.users[client_id].remove_file(file_id)

            return create_delete_response_command(
                f"Access to file {file_id} removed successfully"
            ).to_json()

        # If we reach here, the user doesn't have any permissions to the file
        return create_error_command("Permission denied").to_json()

    def revoke_user(self, payload, client_id: str) -> dict:
        """
        Revoke a user's access to a file.
        Only the file owner can revoke access, and the file must be in their personal vault.
        """
        file_id = payload["file_id"]
        user_id = payload["user_id"]

        if file_id not in self.files:
            return create_error_command("File not found").to_json()

        file = self.files[file_id]

        # Check if client is the owner of the file
        if file.owner_id != client_id:
            return create_error_command("Permission denied").to_json()

        # Check if file is in the user's personal vault (not in a group)
        if not file.path or not file.path.startswith(os.path.join(PATH, client_id)):
            return create_error_command(
                "Operation only allowed for files in personal vault"
            ).to_json()

        # Check if the user has access to the file
        if user_id not in file.listed_users:
            return create_error_command(
                f"User {user_id} does not have access to this file"
            ).to_json()

        # Remove the user's access to the file
        file.remove_user(user_id)

        # Remove all permissions for this user on this file
        self.acess_control.remove_permission(user_id, file_id, Permission.READ)
        self.acess_control.remove_permission(user_id, file_id, Permission.WRITE)

        # Check if the user has the file in their list and remove it
        if user_id in self.users:
            self.users[user_id].remove_file(file_id)

        return create_revoke_response_command(
            f"User {user_id} revoked from file {file_id} successfully"
        ).to_json()

    def list_files(self, payload, client_id: str) -> dict:
        """
        List files according to specified criteria:
        - list (no options): All files the user has access to (personal, shared, and group files)
        - list -u user_id: Files shared with the specified user
        - list -g group_id: Files belonging to a specific group (if client is a member)
        """
        flag = payload.get("flag")
        id_thing = payload.get("id_thing")
        
        files_info = {}
        
        # Case 1: No options - list all files accessible to the client
        if flag is None:
            # Personal and directly shared files
            if client_id in self.acess_control.permissions:
                for file_id, permissions in self.acess_control.permissions.get(client_id, {}).items():
                    if file_id in self.files:
                        file = self.files[file_id]
                        files_info[file_id] = {
                            "name": file.file_name,
                            "owner": file.owner_id,
                            "last_modified": file.modified_at,
                            "last_changed_by": file.last_changed,
                            "permissions": [p.value for p in permissions],
                            "shared": len(file.listed_users) > 1
                        }
            
            # Files accessible through groups
            for group_id, group in self.groups.items():
                if client_id in group.members:
                    for file_id in group.list_of_files:
                        if file_id in self.files and file_id not in files_info:
                            file = self.files[file_id]
                            permissions = []
                            if group_id in self.acess_control.group_acl and client_id in self.acess_control.group_acl[group_id]:
                                if file_id in self.acess_control.group_acl[group_id][client_id]:
                                    permissions = [p.value for p in self.acess_control.group_acl[group_id][client_id][file_id]]
                            
                            files_info[file_id] = {
                                "name": file.file_name,
                                "owner": file.owner_id,
                                "last_modified": file.modified_at,
                                "last_changed_by": file.last_changed,
                                "permissions": permissions,
                                "group": group.group_name,
                                "shared": True
                            }

        # Case 2: List files shared with a specific user
        elif flag == "user":
            user_id = id_thing
            if user_id not in self.users:
                return create_error_command("User not found").to_json()

            # List files that are shared between the client and the specified user
            for file_id, file in self.files.items():
            # Check if the file is shared between these two users (either direction)
                if client_id in file.listed_users and user_id in file.listed_users:
                    # Client is either the owner or has been shared the file
                    if file.owner_id == client_id or file.owner_id == user_id:
                    # Get client's permissions for this file (not the target user's)
                        permissions = [p.value for p in self.acess_control.get_permissions(client_id, file_id)]
                        files_info[file_id] = {
                            "name": file.file_name,
                            "owner": file.owner_id,
                            "last_modified": file.modified_at,
                            "last_changed_by": file.last_changed,
                            "permissions": permissions,
                            "shared": True
                        }

        # Case 3: List files belonging to a specific group
        elif flag == "group":
            group_id = id_thing
            if group_id not in self.groups:
                return create_error_command("Group not found").to_json()
            
            group = self.groups[group_id]
            
            # Check if the user is a member of the group
            if client_id not in group.members:
                return create_error_command("You are not a member of this group").to_json()
            
            # List all files in the group
            for file_id in group.list_of_files:
                if file_id in self.files:
                    file = self.files[file_id]
                    permissions = []
                    if group_id in self.acess_control.group_acl and client_id in self.acess_control.group_acl[group_id]:
                        if file_id in self.acess_control.group_acl[group_id][client_id]:
                            permissions = [p.value for p in self.acess_control.group_acl[group_id][client_id][file_id]]
                    
                    files_info[file_id] = {
                        "name": file.file_name,
                        "owner": file.owner_id,
                        "last_modified": file.modified_at,
                        "last_changed_by": file.last_changed,
                        "permissions": permissions,
                        "shared": True
                    }
        
        file_info_json = dict_to_json(files_info)
        return create_list_response_command(file_info_json).to_json()



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

# In application.py
import os
import sys
from typing import Dict, Any


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.utils import (
    dict_to_json,
    json_to_dict,
)
from common.Icarus_Protocol import (
    create_get,
    create_multi_get,
)
from pprint import (
    pprint_add,
    pprint_details,
    pprint_read,
    pprint_replace,
    pprint_group_create,
    pprint_group_delete,
    pprint_share,
    pprint_group_add_user,
    pprint_group_add_file,
    pprint_group_list,
    pprint_revoke_file,
    pprint_delete_file,
    pprint_list,
)
from common.commands_utils import Command, CMD_TYPES, create_read_response_command
from handlers import (
    create_replace,
    create_share,
    create_group_add_file,
    create_group_add_user,
    handler_add_command,
    handler_delete_command,
    handler_details_command,
    handler_read_command,
    handler_group_create_command,
    handler_group_delete_command,
    handler_group_add_user_command,
    handler_group_add_file_command,
    handler_group_delete_user_command,
    handler_group_list_command,
    handler_revoke_command,
    handler_list_command,
)


def process_cmd(client, c_input: str) -> Dict[str, Any]:
    """
    Process the command given by the user
    Returns a dict with command results for the client to handle
    """
    # Split the message into command and arguments
    parts = c_input.split()

    if not parts:
        return 0

    command = parts[0]

    if command.lower() == "group" and len(parts[1:]) > 0:
        command = command + " " + parts[1]
        args = parts[2:]
    else:
        args = parts[1:]

    try:
        match command.lower():
            case "add":
                if len(args) != 1:
                    print("Invalid number of arguments")
                    return client.process(message="")

                print(f"Adding file: {args[0]}")
                file_path = args[0]
                # Check if the file exists
                if not os.path.exists(file_path):
                    print(f"File {file_path} does not exist.")
                    return client.process(message="")
                # Check if the file is a valid file
                if not os.path.isfile(file_path):
                    print(f"{file_path} is not a valid file.")
                    return client.process(message="")

                command_data = handler_add_command(client, file_path)
                # Create a proper packet for transmission

            case "update":
                pass
            case "list":
                # list [-u user-id | -g group-id]
                if len(args) == 0:
                    command_data = handler_list_command()
                elif len(args) == 2:
                    if args[0] == "-u":
                        # list -u <user-id>
                        user_id = args[1]
                        command_data = handler_list_command("user", user_id)
                    elif args[0] == "-g":
                        # list -g <group-id>
                        group_id = args[1]
                        command_data = handler_list_command("group", group_id)
                    else:
                        print("Invalid arguments")
                        return client.process(message="")

            case "share":
                # share <file-id> <user-id> <permission>

                if len(args) != 3:
                    print("Invalid number of arguments")
                    return client.process(message="")
                file_id = args[0]
                user_id = args[1]
                permission = args[2]

                if permission not in ["read", "write", "w", "r"]:
                    print(f"Permission {permission} is not valid.")
                    return client.process(message="")

                command_data = create_share(file_id, user_id, permission)
                command_data = Command.to_json(command_data)

                command_data = create_get(file_id, command_data)

            case "delete":
                # delete <file-id>
                if len(args) != 1:
                    print("Invalid number of arguments")
                    return client.process(message="")
                file_id = args[0]
                command_data = handler_delete_command(file_id)

            case "replace":

                if len(args) != 2:
                    print("Invalid number of arguments")
                    return client.process(message="")
                file_id = args[0]
                file_path = args[1]
                # Check if the file exists
                if not os.path.exists(file_path):
                    print(f"File {file_path} does not exist.")
                    return client.process(message="")
                # Check if the file is a valid file
                if not os.path.isfile(file_path):
                    print(f"{file_path} is not a valid file.")
                    return client.process(message="")

                command_data = create_replace(file_id, file_path)

                command_data = Command.to_json(command_data)
                # get_packet
                command_data = create_get(file_id, command_data)

            case "details":

                if len(args) != 1:
                    print("Invalid number of arguments")
                    return client.process(message="")

                file_id = args[0]

                command_data = handler_details_command(file_id)

            case "revoke":
                # revoke <file-id> <user-id>
                if len(args) != 2:
                    print("Invalid number of arguments")
                    return client.process(message="")
                file_id = args[0]
                user_id = args[1]

                command_data = handler_revoke_command(file_id, user_id)

            case "read":
                if len(args) != 1:
                    print("Invalid number of arguments")
                    return client.process(message="")

                file_id = args[0]

                command_data = handler_read_command(file_id)

            case "group create":

                if len(args) != 1:
                    print("Invalid number of arguments")
                    return client.process(message="")
                print(f"Creating group: {args[0]}")
                group_name = args[0]

                command_data = handler_group_create_command(group_name)
            case "group delete":
                if len(args) != 1:
                    print("Invalid number of arguments")
                    return client.process(message="")

                print(f"Deleting group: {args[0]}")
                group_id = args[0]

                command_data = handler_group_delete_command(group_id)

            case "group add-user":
                # group add-user <group-id> <user-id> <permissions>
                if len(args) != 3:
                    print("Invalid number of arguments")
                    return client.process(message="")
                group_id = args[0]
                user_id = args[1]
                permission = args[2]

                if permission not in ["read", "write", "w", "r"]:
                    print(f"Permission {permission} is not valid.")
                    return client.process(message="")

                command_data = create_group_add_user(group_id, user_id, permission)
                command_data = Command.to_json(command_data)
                command_data = create_multi_get(group_id, command_data)

            case "group delete-user":
                # group delete-user <group-id> <user-id>
                if len(args) != 2:
                    print("Invalid number of arguments")
                    return client.process(message="")
                group_id = args[0]
                user_id = args[1]

                command_data = handler_group_delete_user_command(group_id, user_id)

                pass
            case "group list":
                # group list
                command_data = handler_group_list_command()

            case "group add":
                # group add <group-id> <file-path>
                if len(args) != 2:
                    print("Invalid number of arguments")
                    return client.process(message="")
                group_id = args[0]
                file_path = args[1]
                # Check if the file exists
                if not os.path.exists(file_path):
                    print(f"File {file_path} does not exist.")
                    return client.process(message="")
                # Check if the file is a valid file
                if not os.path.isfile(file_path):
                    print(f"{file_path} is not a valid file.")
                    return client.process(message="")

                command_data = create_group_add_file(group_id, file_path)

                command_data = Command.to_json(command_data)

                command_data = create_multi_get(group_id, command_data)

            case _:
                return client.process(message="")

        return command_data.to_json()

    except Exception as e:
        print(f"Error processing command: {e}")
        return 0


def process_response(client, response: str, key=None) -> None:
    """
    Process the response from the server
    """
    response = Command.from_json(response)

    match response.type:
        case CMD_TYPES.ADD:
            pprint_add(response.payload)
        case CMD_TYPES.DETAILS:

            pprint_details(response.payload)

        case CMD_TYPES.READ:
            print("........................................")
            pprint_read(client, response.payload, key)

        case CMD_TYPES.REPLACE:
            print("........................................")
            pprint_replace(response.payload["msg"])

        case CMD_TYPES.G_CREATE:
            print("........................................")
            pprint_group_create(response.payload)
        case CMD_TYPES.G_DELETE:
            print("........................................")
            pprint_group_delete(response.payload)
        case CMD_TYPES.SHARE:
            print("........................................")
            pprint_share(response.payload)

        case CMD_TYPES.G_ADD_USER:
            print("........................................")
            pprint_group_add_user(response.payload)

        case CMD_TYPES.G_ADD:
            print("........................................")
            pprint_group_add_file(response.payload)
        case CMD_TYPES.G_LIST:
            print("........................................")
            pprint_group_list(response.payload)

        case CMD_TYPES.DELETE:
            print("........................................")
            pprint_delete_file(response.payload)

        case CMD_TYPES.REVOKE:
            print("........................................")
            pprint_revoke_file(response.payload)

        case CMD_TYPES.LIST:
            print("........................................")
            pprint_list(response.payload)

        case _:
            print("Unknown response type")


def process_share_partII(comando: dict):

    command_data = create_share(
        file_id=comando["file_id"],
        user_id=comando["user_id"],
        permissions=comando["permissions"],
        file_key=comando["file_key"],
    )

    command_data = Command.to_json(command_data)

    command_data = create_get(comando["user_id"], command_data)

    return command_data.to_json()


def process_get_partII(comando: dict, last_changed: str):
    """
    Process the get command
    """

    command_data = create_read_response_command(
        key=comando["key"],
        content=comando["content"],
        file_hash=comando["file_hash"],
        signature=comando["signature"],
        last_modified=last_changed,
    )

    command_data = Command.to_json(command_data)
    command_data = create_get(last_changed, command_data)

    return command_data.to_json()


def process_group_add_user_partII(comando: dict):
    """
    Process the group add user command
    """

    dict_keys = comando["id"]
    dict_keys_json = dict_to_json(dict_keys)

    comando = Command.from_json(comando["command"])

    commando_data = create_group_add_user(
        comando.payload["group_id"],
        comando.payload["user_id"],
        comando.payload["permissions"],
        dict_keys_json,
    )

    commando_data = Command.to_json(commando_data)
    commando_data = create_get(comando.payload["user_id"], commando_data)

    return commando_data.to_json()

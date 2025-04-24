# In application.py
import os
import sys
from typing import Dict, Any


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from pprint import (
    pprint_add,
    pprint_details,
    pprint_read,
)
from common.commands_utils import Command, CMD_TYPES
from handlers import (
    handler_add_command,
    handler_details_command,
    handler_read_command,
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
                    return 0

                print(f"Adding file: {args[0]}")
                file_path = args[0]
                # Check if the file exists
                if not os.path.exists(file_path):
                    print(f"File {file_path} does not exist.")
                    return 0
                # Check if the file is a valid file
                if not os.path.isfile(file_path):
                    print(f"{file_path} is not a valid file.")
                    return 0

                command_data = handler_add_command(client, file_path)
                # Create a proper packet for transmission

            case "update":
                pass
            case "list":
                pass
            case "share":
                pass
            case "delete":
                pass

            case "replace":
                pass
            case "details":

                if len(args) != 1:
                    return 0

                file_id = args[0]

                command_data = handler_details_command(file_id)

            case "revoke":
                pass

            case "read":
                if len(args) != 1:
                    return 0

                file_id = args[0]

                command_data = handler_read_command(file_id)

            case "group create":
                pass

            case "group delete":
                pass

            case "group add-user":
                pass

            case "group delete-user":
                pass
            case "group list":
                pass

            case "group add":
                pass
            case "exit":
                pass

            case "get":
                pass
            case _:
                print(f"Unknown command: {command}")
                return 0

        return command_data.to_json().encode("utf-8")

    except Exception as e:
        print(f"Error processing command: {e}")
        return 0


def process_response(client, response: str) -> None:
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
            pprint_read(client, response.payload)

        case CMD_TYPES.GET:

            print(response.payload)

        case _:
            print("Unknown response type")



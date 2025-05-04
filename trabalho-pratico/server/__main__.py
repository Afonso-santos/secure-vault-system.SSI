import os
import sys
import pathlib
import asyncio
import base64
from datetime import datetime, timezone

from cryptography.x509 import Certificate, load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives import hashes

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.utils import get_userdata, json_to_dict, dict_to_json
from common.certificate_validator import CertificateValidator
from common.commands_utils import CMD_TYPES
from common.commands_utils import Command
from file_system import FileSystem


# from common.file_system import FileSystem
from common.Icarus_Protocol import (
    Packet,
    PacketType,
    create_server_hello,
    create_server_auth,
    create_change_cipher_spec,
    create_finished,
    create_data_exchange,
    create_ack,
    create_error,
    derive_keys,
    encrypt_data,
    decrypt_data,
    create_get,
    create_multi_get,
)

# Constants
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 7777
MAX_MSG_SIZE = 8192
SERVER_PATH = None


SERVER_INSTANCE = None


class Server:

    def __init__(self, path_to_server_cert: str):
        self.name = None
        self.private_key = None
        self.public_key = None
        self.user_cert: Certificate = None
        self.ca_cert: Certificate = None

        self.session_key = {}

        self.name, self.private_key, self.user_cert, self.ca_cert = get_userdata(
            path_to_server_cert
        )

        self.public_key = self.user_cert.public_key()

        self.certificate_validator = CertificateValidator(self.ca_cert)

        self.file_system = FileSystem()

        if not (
            self.certificate_validator.validate_certificate(self.user_cert, self.name)
        ):
            raise ValueError("Inavelid client certificate")

        # Server's process function:

    def process(self, message: bytes = b"", client_id=None) -> int | bytes:
        # Store client state using client_id
        if client_id and client_id not in self.session_key:
            self.session_key[client_id] = {
                "name": None,
                "nonce": None,
                "time_stamp": None,
                "server_random": None,
                "client_random": None,
                "key": None,
                "client_cert": None,
                "handshake_complete": False,
            }

        client_state = self.session_key.get(client_id, {})

        if message:
            message = Packet.from_json(message.decode())
            match message.type:
                case PacketType.CLIENT_HELLO:
                    client_cert = message.payload["certificate"]
                    client_cert_name = message.payload["certificade_name"]

                    # Decode the client certificate
                    client_cert = base64.b64decode(client_cert)
                    client_cert = load_pem_x509_certificate(client_cert)

                    # Validate the client certificate
                    if not self.certificate_validator.validate_certificate(
                        client_cert, client_cert_name
                    ):
                        print("❌ Invalid client certificate")
                        return -1

                    # Store client certificate
                    client_state["client_cert"] = client_cert
                    client_state["name"] = client_cert_name

                    # Generate and encrypt nonce with client's public key
                    nonce = os.urandom(16)
                    encrypted_nonce = client_cert.public_key().encrypt(
                        nonce,
                        asymmetric.padding.OAEP(
                            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )

                    # Store nonce
                    client_state["nonce"] = nonce
                    client_state["time_stamp"] = datetime.now(timezone.utc).timestamp()

                    self.session_key[client_id] = client_state

                    # Create SERVER_HELLO response
                    server_hello_packet = create_server_hello(
                        self.name,
                        self.user_cert.public_bytes(Encoding.PEM),
                        encrypted_nonce,
                    )

                    return server_hello_packet.to_json().encode()

                case PacketType.CLIENT_AUTH:
                    client_nonce = message.payload["client_nonce"]
                    server_nonce = message.payload["server_nonce"]
                    signature = message.payload["signature"]

                    # Decode the client nonce and signature
                    client_nonce = base64.b64decode(client_nonce)
                    server_nonce = base64.b64decode(server_nonce)
                    signature = base64.b64decode(signature)

                    # Verify the signature using client's certificate
                    client_cert = client_state.get("client_cert")
                    if not client_cert:
                        print("❌ No client certificate found")
                        return -1

                    # Verify signature
                    try:
                        client_cert.public_key().verify(
                            signature,
                            server_nonce,
                            asymmetric.padding.PSS(
                                mgf=asymmetric.padding.MGF1(hashes.SHA256()),
                                salt_length=asymmetric.padding.PSS.MAX_LENGTH,
                            ),
                            hashes.SHA256(),
                        )
                    except Exception as e:
                        print(f"❌ Invalid signature: {e}")
                        return -1

                    # Decrypt client nonce with our private key
                    client_nonce = self.private_key.decrypt(
                        client_nonce,
                        asymmetric.padding.OAEP(
                            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )

                    # Sign the client nonce
                    signature = self.private_key.sign(
                        client_nonce,
                        asymmetric.padding.PSS(
                            mgf=asymmetric.padding.MGF1(hashes.SHA256()),
                            salt_length=asymmetric.padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )

                    if (
                        client_state["nonce"] != server_nonce
                        and client_state["time_stamp"] + 60
                        < datetime.now(timezone.utc).timestamp()
                    ):
                        print("❌ Invalid nonce or expired timestamp")
                        return -1

                    client_state["nonce"] = None
                    client_state["time_stamp"] = None

                    # Generate server random
                    server_random = os.urandom(32)
                    client_state["server_random"] = server_random
                    self.session_key[client_id] = client_state

                    # Encrypt server random with client's public key
                    encrypted_server_random = client_cert.public_key().encrypt(
                        server_random,
                        asymmetric.padding.OAEP(
                            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )

                    # Create SERVER_AUTH response
                    server_auth_packet = create_server_auth(
                        client_nonce,
                        encrypted_server_random,
                        signature,
                    )

                    return server_auth_packet.to_json().encode()

                case PacketType.KEY_EXCHANGE:

                    encrypted_client_random = base64.b64decode(
                        message.payload["client_random"]
                    )

                    client_random = self.private_key.decrypt(
                        encrypted_client_random,
                        asymmetric.padding.OAEP(
                            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )

                    # Store client random
                    client_state["client_random"] = client_random

                    # Derive session key from client and server random
                    session_key = derive_keys(
                        client_random,
                        client_state["server_random"],
                    )

                    # Store session key
                    client_state["key"] = session_key
                    self.session_key[client_id] = client_state

                    # Send CHANGE_CIPHER_SPEC to client
                    change_cipher_spec_packet = create_change_cipher_spec("AES-256-GCM")
                    return change_cipher_spec_packet.to_json().encode()

                case PacketType.FINISH:
                    # Extract finish data
                    finish_data = message.payload.get("change_spec", "")
                    print(f"Finish data: {finish_data}")

                    # In a real system, verify the finish data contains the correct handshake hash

                    # Mark handshake as complete
                    client_state["handshake_complete"] = True
                    self.session_key[client_id] = client_state

                    self.file_system.add_user(client_state["name"], client_id)

                    # Send our own FINISH packet
                    finish_packet = create_finished(True)  # Simplified value for demo
                    return finish_packet.to_json().encode()

                case PacketType.DATA_EXCHANGE:

                    if not client_state.get("handshake_complete", False):
                        print("❌ Received data before handshake completion")
                        return create_error().to_json().encode()

                    try:
                        encrypted_data = base64.b64decode(
                            message.payload["data"].encode()
                        )
                        iv = base64.b64decode(message.payload["iv"].encode())
                        auth_tag = base64.b64decode(
                            message.payload["auth_tag"].encode()
                        )

                    except Exception as e:
                        print(f"❌ Base64 decoding error: {e}")
                        return create_error().to_json().encode()

                    try:
                        decrypted_data = decrypt_data(
                            encrypted_data, client_state["key"], iv, auth_tag
                        )
                        print(f"🔑 Decrypted data: {decrypted_data.decode('utf-8')}")

                        comando = Command.from_json(
                            decrypted_data.decode("utf-8")
                        )  # Convert to Command object
                        match comando.type:
                            case CMD_TYPES.GET:
                                return self.process(decrypted_data, client_id)
                            case CMD_TYPES.MULTI_GET:
                                print("MULTI_GET")
                                return self.process(decrypted_data, client_id)

                            case _:
                                response_data = self.file_system.proccess_cmd(
                                    decrypted_data.decode("utf-8"), client_state["name"]
                                )

                                enc_data, enc_iv, enc_tag = encrypt_data(
                                    response_data.encode(), client_state["key"]
                                )
                                data_exchange_packet = create_data_exchange(
                                    enc_data, enc_iv, enc_tag
                                )
                                return data_exchange_packet.to_json().encode()

                    except Exception as e:
                        print(f"Decryption error: {e}")
                        return create_error().to_json().encode()

                case PacketType.ACK:
                    print("Received ACK")

                    return create_ack().to_json().encode()
                case PacketType.GET:
                    id_thing = message.payload["id"]

                    commando = message.payload["command"]

                    key = self.file_system.get_thing(id_thing, client_state["name"])
                    if key:

                        data = create_get(id_thing, commando, key)
                        enc_data, enc_iv, enc_tag = encrypt_data(
                            data.to_json().encode(), client_state["key"]
                        )
                        data_exchange_packet = create_data_exchange(
                            enc_data, enc_iv, enc_tag
                        )

                        return data_exchange_packet.to_json().encode()
                    else:
                        print("File not found")
                        return create_error().to_json().encode()
                case PacketType.MULTI_GET:

                    id_thing = message.payload["id"]

                    commando = message.payload["command"]
                    commando = Command.from_json(commando)
                    things = self.file_system.get_thing(id_thing)
                    things_dict = {}
                    if things:
                        if commando.type == CMD_TYPES.G_ADD:

                            thing_dict = {member: None for member in things.members}

                            thing_dict_json = dict_to_json(thing_dict)

                            commando = Command.to_json(commando)
                            data = create_multi_get(thing_dict_json, commando)
                            enc_data, enc_iv, enc_tag = encrypt_data(
                                data.to_json().encode(), client_state["key"]
                            )
                            data_exchange_packet = create_data_exchange(
                                enc_data, enc_iv, enc_tag
                            )

                            return data_exchange_packet.to_json().encode()

                        elif commando.type == CMD_TYPES.G_ADD_USER:

                            for file_id in things.list_of_files:
                                file = self.file_system.files.get(file_id)
                                key = file.listed_users.get(client_state["name"])
                                things_dict[file_id] = key

                            if len(things_dict) == 0:
                                data = self.file_system.proccess_cmd(
                                    commando.to_json(), client_state["name"]
                                )

                                enc_data, enc_iv, enc_tag = encrypt_data(
                                    data.encode(), client_state["key"]
                                )
                                print(f"data: {data}")
                                data_exchange_packet = create_data_exchange(
                                    enc_data, enc_iv, enc_tag
                                )
                                return data_exchange_packet.to_json().encode()

                            else:
                                things_dict_json = dict_to_json(things_dict)

                                commando = Command.to_json(commando)
                                data = create_multi_get(things_dict_json, commando)
                                enc_data, enc_iv, enc_tag = encrypt_data(
                                    data.to_json().encode(), client_state["key"]
                                )
                                data_exchange_packet = create_data_exchange(
                                    enc_data, enc_iv, enc_tag
                                )
                                return data_exchange_packet.to_json().encode()

                    else:
                        print("File not found")
                        return create_error().to_json().encode()

                case _:
                    print(f"Unknown message type: {message.type}")
                    return create_error().to_json().encode()

        return -1


async def handle_echo(reader, writer):
    addr = writer.get_extra_info(
        "peername"
    )  # Using peername instead of socket for better readability
    client_id = id(writer)  # Use a unique ID for this client

    print(f"Connection from {addr} established.")

    try:
        while not reader.at_eof():
            data = await reader.read(MAX_MSG_SIZE)
            if not data:
                break

            response = SERVER_INSTANCE.process(data, client_id)
            if response == -1:
                print("Error processing message")
                break

            if response:
                try:
                    writer.write(response)
                    await writer.drain()
                except ConnectionError as e:
                    print(f"Connection error while writing: {e}")
                    break
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        try:
            print(f"Connection from {addr} closed.")
            writer.close()
            if not writer.is_closing():
                await writer.wait_closed()
        except Exception as e:
            print(f"Error during connection cleanup: {e}")


async def tcp_receiver(server_cert_path: str):
    global SERVER_INSTANCE
    SERVER_INSTANCE = Server(server_cert_path)

    server = await asyncio.start_server(handle_echo, SERVER_HOST, SERVER_PORT)

    print(f"Serving on {server.sockets[0].getsockname()}")
    print("  (type ^C to finish)\n")

    async with server:
        await server.serve_forever()


def main(args):
    if len(args) < 1:
        print("Usage: python -m server <p12_file>")
        return 1

    server_cert_path = args[0]
    if not pathlib.Path(server_cert_path).is_file():
        print(f"File {server_cert_path} doesn't exist.")
        return 1  # Return error code when file doesn't exist

    # Run the server
    try:
        asyncio.run(tcp_receiver(server_cert_path))
        return 0
    except KeyboardInterrupt:
        print("\nServer interrupted by user.")
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

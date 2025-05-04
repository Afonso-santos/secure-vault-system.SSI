import os
import sys
import asyncio
import base64
from datetime import datetime, timezone

from cryptography.x509 import Certificate, load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from application import (
    process_cmd,
    process_response,
    process_share_partII,
    process_get_partII,
    process_group_add_user_partII,
)
from common.utils import get_userdata, json_to_dict
from common.certificate_validator import CertificateValidator
from common.commands_utils import CMD_TYPES, Command
from handlers import (
    handler_replace_command,
    handler_share_command,
    handler_group_add_file_command,
    handler_group_add_user_command,
)
from common.Icarus_Protocol import (
    Packet,
    PacketType,
    create_client_hello,
    create_client_auth,
    create_key_exchange,
    create_finished,
    create_data_exchange,
    create_ack,
    create_error,
    create_get,
    encrypt_data,
    decrypt_data,
    derive_keys,
)

CA_HOST = "127.0.0.1"
CA_PORT = 8888

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 7777

MAX_MSG_SIZE = 8192


class Client:
    def __init__(self, path_to_client_cert: str):
        self.name = None
        self.private_key = None
        self.public_key = None
        self.user_cert: Certificate = None
        self.ca_cert: Certificate = None

        self.handshake_complete = False
        self.handshake_with_ca_complete = False  # Track CA handshake separately
        self.handshake_with_server_complete = False  # Track server handshake separately

        self.client_random = None
        self.server_random = None

        self.client_random_ca = None
        self.server_random_ca = None

        self.session_key_ca = None
        self.session_key_server = None

        self.server_cert = None
        self.nonce = None
        self.time_stamp = None

        self.name, self.private_key, self.user_cert, self.ca_cert = get_userdata(
            path_to_client_cert
        )
        self.public_key = self.user_cert.public_key()

        self.certificate_validator = CertificateValidator(self.ca_cert)

        self.target = None

        if not (
            self.certificate_validator.validate_certificate(self.user_cert, self.name)
        ):
            raise ValueError("Invalid client certificate")

    def process_handshake(
        self, message: bytes = None, target: str = None
    ) -> tuple[str, bytes]:
        """
        Process handshake messages.
        Returns a tuple of (target, message) where target is 'ca', 'server', or None.
        """
        if not message:
            # Initial handshake - start with CA
            if not self.handshake_with_ca_complete:
                return (
                    "ca",
                    create_client_hello(
                        self.user_cert.public_bytes(Encoding.PEM), self.name
                    )
                    .to_json()
                    .encode(),
                )
            # Then move to server
            elif not self.handshake_with_server_complete:
                return (
                    "server",
                    create_client_hello(
                        self.user_cert.public_bytes(Encoding.PEM), self.name
                    )
                    .to_json()
                    .encode(),
                )
            else:
                self.handshake_complete = True
                return None, b""  # All handshakes complete

        # Process incoming message
        packet = Packet.from_json(message.decode())

        match packet.type:
            case PacketType.SERVER_HELLO:
                server_cert = packet.payload["certificade"]
                server_cert_name = packet.payload["certificade_name"]
                server_nonce = packet.payload["server_nonce"]

                server_cert = base64.b64decode(server_cert)
                server_nonce = base64.b64decode(server_nonce)
                self.server_cert = load_pem_x509_certificate(server_cert)

                if not self.certificate_validator.validate_certificate(
                    self.server_cert, server_cert_name
                ):
                    print("❌ Invalid server certificate")
                    return None, b"-1"

                try:
                    server_nonce = self.private_key.decrypt(
                        server_nonce,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )
                except Exception as e:
                    print(f"❌ Decryption failed: {e}")
                    return None, b"-1"

                self.nonce = os.urandom(16)
                self.time_stamp = datetime.now(timezone.utc).timestamp()

                nonce = self.server_cert.public_key().encrypt(
                    self.nonce,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )

                signature = self.private_key.sign(
                    server_nonce,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )

                message = create_client_auth(server_nonce, nonce, signature)
                return target, message.to_json().encode()

            case PacketType.SERVER_AUTH:
                client_nonce = base64.b64decode(packet.payload["client_nonce"])

                encrypted_server_random = base64.b64decode(
                    packet.payload["server_random"]
                )

                server_random = self.private_key.decrypt(
                    encrypted_server_random,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )

                signature = base64.b64decode(packet.payload["signature"])

                try:
                    self.server_cert.public_key().verify(
                        signature,
                        client_nonce,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )
                except Exception as e:
                    print(f"❌ Invalid signature: {e}")
                    return None, b"-1"

                if (
                    self.nonce != client_nonce
                    or self.time_stamp + 60 < datetime.now(timezone.utc).timestamp()
                ):
                    print("❌ Invalid nonce or expired timestamp")
                    return None, b"-1"

                # Generate and derive keys for CA or server
                if target == "ca":
                    self.client_random_ca = os.urandom(32)

                    encrypted_client_random = self.server_cert.public_key().encrypt(
                        self.client_random_ca,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )

                    self.server_random_ca = server_random
                    self.session_key_ca = derive_keys(
                        self.client_random_ca, self.server_random_ca
                    )
                    message = create_key_exchange(encrypted_client_random)
                else:
                    self.client_random = os.urandom(32)

                    encrypted_client_random = self.server_cert.public_key().encrypt(
                        self.client_random,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )

                    self.server_random = server_random
                    self.session_key_server = derive_keys(
                        self.client_random, self.server_random
                    )
                    message = create_key_exchange(encrypted_client_random)

                return target, message.to_json().encode()

            case PacketType.CHANGE_CIPHER_SPEC:
                cipher_spec = packet.payload["change_spec"]

                if cipher_spec != "AES-256-GCM":
                    print(f"❌ Unsupported cipher spec: {cipher_spec}")
                    return target, create_error().to_json().encode()

                finish_message = create_finished(True)
                return target, finish_message.to_json().encode()

            case PacketType.FINISH:
                print(f"✅ Handshake complete with {target}")

                if target == "ca":
                    self.handshake_with_ca_complete = True
                    return (
                        "server",
                        create_client_hello(
                            self.user_cert.public_bytes(Encoding.PEM), self.name
                        )
                        .to_json()
                        .encode(),
                    )
                elif target == "server":
                    self.handshake_with_server_complete = True
                    self.handshake_complete = True
                    return None, b""

            case PacketType.ERROR:
                print("❌ Error during handshake")
                return None, b"-1"

            case _:
                print(f"❌ Unexpected handshake message type: {packet.type}")
                return None, b"-1"

    def process_message(self, message: bytes = None) -> tuple[str, bytes]:
        """
        Process application messages after handshake is complete.
        Returns a tuple of (target, message) where target is 'server', 'ca', or None.
        """
        if message:
            try:
                packet = Packet.from_json(message.decode())

                # target = packet.source if hasattr(packet, 'source') else 'server'

                session_key = (
                    self.session_key_ca
                    if self.target == "ca"
                    else self.session_key_server
                )

                match packet.type:
                    case PacketType.DATA_EXCHANGE:
                        encrypted_data = base64.b64decode(packet.payload["data"])
                        iv = base64.b64decode(packet.payload["iv"])
                        auth_tag = base64.b64decode(packet.payload["auth_tag"])

                        try:
                            decrypted_data = decrypt_data(
                                encrypted_data, session_key, iv, auth_tag
                            )

                            try:
                                comando = Command.from_json(
                                    decrypted_data.decode("utf-8")
                                )

                                if comando.type == CMD_TYPES.GET:
                                    return self.process_message(decrypted_data)
                                elif comando.type == CMD_TYPES.MULTI_GET:
                                    return self.process_message(decrypted_data)

                                elif comando.type == CMD_TYPES.READ:
                                    comando = Command.from_json(
                                        decrypted_data.decode("utf-8")
                                    )
                                    last_changed = comando.payload.get("last_modified")
    
                                    if last_changed != self.name:
                                        

                                        message = process_get_partII(
                                            comando.payload, last_changed
                                        )

                                        

                                        encrypted_data, iv, auth_tag = encrypt_data(
                                            message.encode(),
                                            self.session_key_ca,
                                        )
                                        self.target = "ca"
                                        return (
                                            "ca",
                                            create_data_exchange(
                                                encrypted_data, iv, auth_tag
                                            )
                                            .to_json()
                                            .encode(),
                                        )
                                    
                                    # return self.target, create_ack().to_json().encode()

                                process_response(
                                    self,
                                    decrypted_data.decode("utf-8"),
                                )

                            except Exception as e:
                                print(f"⚠️ Not a command format: {e}")

                            return self.target, create_ack().to_json().encode()

                        except Exception as e:
                            print(f"❌ Decryption error: {e}")
                            return self.target, create_error().to_json().encode()
                    case PacketType.MULTI_GET:

                        if self.target == "server":
                            encrypted_data, iv, auth_tag = encrypt_data(
                                message,
                                self.session_key_ca,
                            )

                            self.target = "ca"
                            return (
                                "ca",
                                create_data_exchange(encrypted_data, iv, auth_tag)
                                .to_json()
                                .encode(),
                            )
                        elif self.target == "ca":
                            self.target = "server"

                            comando = Command.from_json(packet.payload.get("command"))
                            if comando.type == CMD_TYPES.G_ADD:

                                id_things = packet.payload.get("id")
                                group_id = comando.payload.get("group_id")
                                file_path = comando.payload.get("file_path")

                                message_cmd = handler_group_add_file_command(
                                    self, group_id, file_path, id_things
                                )

                                encrypted_data, iv, auth_tag = encrypt_data(
                                    message_cmd.to_json().encode("utf-8"),
                                    self.session_key_server,
                                )

                                return (
                                    "server",
                                    create_data_exchange(encrypted_data, iv, auth_tag)
                                    .to_json()
                                    .encode(),
                                )
                            elif comando.type == CMD_TYPES.G_ADD_USER:
                                if self.target == "server":
                                    message_cmd = process_group_add_user_partII(
                                        packet.payload
                                    )

                                    encrypted_data, iv, auth_tag = encrypt_data(
                                        message_cmd.encode(),
                                        self.session_key_ca,
                                    )
                                    self.target = "ca"
                                    return (
                                        "ca",
                                        create_data_exchange(
                                            encrypted_data, iv, auth_tag
                                        )
                                        .to_json()
                                        .encode(),
                                    )
                                elif self.target == "ca":
                                    print("receive message of ca")

                    case PacketType.ACK:
                        
                        return None, b""

                    case PacketType.GET:
                        key = packet.payload.get("key")
                        command_json = packet.payload.get("command")

                        try:
                            command = Command.from_json(command_json)

                            match command.type:
                                case CMD_TYPES.REPLACE:
                                    file_id = command.payload.get("file_id")
                                    file_path = command.payload.get("file_path")

                                    message_cmd = handler_replace_command(
                                        self, file_id, file_path, key
                                    )

                                    encrypted_data, iv, auth_tag = encrypt_data(
                                        message_cmd.to_json().encode("utf-8"),
                                        self.session_key_server,
                                    )

                                    return (
                                        "server",
                                        create_data_exchange(
                                            encrypted_data, iv, auth_tag
                                        )
                                        .to_json()
                                        .encode(),
                                    )

                                case CMD_TYPES.SHARE:

                                    if command.payload.get("file_key") is None:

                                        command.payload["file_key"] = key
                                        message = process_share_partII(command.payload)

                                        encrypted_data, iv, auth_tag = encrypt_data(
                                            message.encode(),
                                            self.session_key_ca,
                                        )
                                        self.target = "ca"
                                        return (
                                            "ca",
                                            create_data_exchange(
                                                encrypted_data, iv, auth_tag
                                            )
                                            .to_json()
                                            .encode(),
                                        )
                                    elif command.payload.get("client_key") is None:

                                        file_id = command.payload.get("file_id")
                                        user_id = command.payload.get("user_id")
                                        permissions = command.payload.get("permissions")
                                        file_key = command.payload.get("file_key")

                                        messsag_cmd = handler_share_command(
                                            self,
                                            file_id,
                                            user_id,
                                            permissions,
                                            file_key,
                                            key,
                                        )

                                        encrypted_data, iv, auth_tag = encrypt_data(
                                            messsag_cmd.to_json().encode("utf-8"),
                                            self.session_key_server,
                                        )

                                        self.target = "server"
                                        return (
                                            "server",
                                            create_data_exchange(
                                                encrypted_data, iv, auth_tag
                                            )
                                            .to_json()
                                            .encode(),
                                        )

                                case CMD_TYPES.READ:
                                    
                                    output = command.to_json()
                                    

                                    process_response(self, output, key)

                                case CMD_TYPES.G_ADD_USER:
                                    

                                    group_id = command.payload.get("group_id")
                                    user_id = command.payload.get("user_id")
                                    permissions = command.payload.get("permissions")
                                    dict_key = command.payload.get("dict_key")

                                    command_data = handler_group_add_user_command(
                                        self,
                                        group_id,
                                        user_id,
                                        permissions,
                                        dict_key,
                                        key,
                                    )

                                    encrypted_data, iv, auth_tag = encrypt_data(
                                        command_data.to_json().encode("utf-8"),
                                        self.session_key_server,
                                    )
                                    self.target = "server"
                                    return (
                                        "server",
                                        create_data_exchange(
                                            encrypted_data, iv, auth_tag
                                        )
                                        .to_json()
                                        .encode(),
                                    )

                        except Exception as e:
                            print(f"❌ Error processing GET command: {e}")
                            return "server", create_error().to_json().encode()

                    case PacketType.ERROR:
                        print("❌ Received ERROR during data exchange")
                        return None, b""

                    case _:
                        print(f"❌ Unknown message type: {packet.type}")
                        return "server", create_error().to_json().encode()

            except Exception as e:
                print(f"❌ Error processing message: {e}")
                return None, b""

        else:
            print("🔒 Secure session established. You can send commands.")
            self.target = "server"
            message = input("Enter data to send:\n-->> ")
            if message:
                if message.lower() == "exit":
                    print("Exiting...")
                    return None, b"-1"

                message = process_cmd(self, message)
                encrypted_data, iv, auth_tag = encrypt_data(
                    message.encode(), self.session_key_server
                )
                message = create_data_exchange(encrypted_data, iv, auth_tag)
                return "server", message.to_json().encode()

            return None, b""

        return None, b""


async def tcp_sender_dual_server(path_to_client_cert: str):
    # Connect to CA Server
    print(f"Connecting to CA server at {CA_HOST}:{CA_PORT}...")
    ca_reader, ca_writer = await asyncio.open_connection(CA_HOST, CA_PORT)
    print("✅ Connected to CA server")

    # Connect to App Server
    print(f"Connecting to application server at {SERVER_HOST}:{SERVER_PORT}...")
    server_reader, server_writer = await asyncio.open_connection(
        SERVER_HOST, SERVER_PORT
    )
    print("✅ Connected to application server")

    client = Client(path_to_client_cert)

    try:
        # Start with handshake phase
        target, message = client.process_handshake()

        while True:
            if message == b"-1":
                print("❌ Fatal error in protocol - exiting")
                break

            if message:
                # Send message based on target
                if target == "ca":
                    print("📤 Sending to CA server...")
                    ca_writer.write(message)
                    await ca_writer.drain()
                    data = await ca_reader.read(MAX_MSG_SIZE)
                    print("📥 Received from CA server")

                    # Process the CA server response
                    if not client.handshake_complete:
                        target, message = client.process_handshake(data, "ca")
                    else:
                        # We shouldn't normally communicate with CA after handshake
                        target, message = client.process_message(data)

                elif target == "server":
                    print("📤 Sending to application server...")
                    server_writer.write(message)
                    await server_writer.drain()
                    data = await server_reader.read(MAX_MSG_SIZE)
                    print("📥 Received from application server")

                    # Process the app server response
                    if not client.handshake_complete:
                        target, message = client.process_handshake(data, "server")
                    else:
                        target, message = client.process_message(data)

                else:
                    print(f"❌ Unknown target: {target}")
                    break
            else:
                if client.handshake_complete:
                    # Application phase - get user input
                    # Wait for user input or server message
                    target, message = client.process_message()

                    # Check for incoming messages from server
                    if not message:  # No user input, check for server messages
                        try:
                            # Set a small timeout to not block forever
                            data = await asyncio.wait_for(
                                server_reader.read(MAX_MSG_SIZE), timeout=0.5
                            )
                            if data:
                                target, message = client.process_message(data)
                        except asyncio.TimeoutError:
                            # No incoming message, just continue
                            await asyncio.sleep(0.1)
                            continue
                else:
                    # Still in handshake phase but no message to send
                    # This might be an intermediate state or an error
                    await asyncio.sleep(0.1)

    except KeyboardInterrupt:
        print("\n🔒 Client interrupted. Closing connections...")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        print("Closing connections...")
        server_writer.write(b"\n")
        server_writer.close()
        await server_writer.wait_closed()
        ca_writer.close()
        await ca_writer.wait_closed()
        print("✅ Connections closed")


def main(args):
    # python client certificates/VAULT_CLI1.p12
    if len(args) < 1:
        print("Usage: python client <path_to_client_cert>")
        return 0

    client_cert_path = args[0]
    if not os.path.exists(client_cert_path):
        print(f"Client certificate not found: {client_cert_path}")
        return 0

    try:
        return asyncio.run(tcp_sender_dual_server(client_cert_path))
    except KeyboardInterrupt:
        print("\nClient interrupted. Exiting...")
        return 0


if __name__ == "__main__":
    main(sys.argv[1:])

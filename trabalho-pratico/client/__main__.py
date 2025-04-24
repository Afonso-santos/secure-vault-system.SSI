import os
import sys
import asyncio
import base64

from cryptography.x509 import Certificate, load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.utils import get_userdata
from common.certificate_validator import CertificateValidator
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
    encrypt_data,
    decrypt_data,
    derive_keys,
)

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

        self.client_random = None
        self.server_random = None
        self.session_key = None

        self.server_cert = None
        self.nonce = None

        self.name, self.private_key, self.user_cert, self.ca_cert = get_userdata(
            path_to_client_cert
        )
        self.public_key = self.user_cert.public_key()

        self.certificate_validator = CertificateValidator(self.ca_cert)

        if not (
            self.certificate_validator.validate_certificate(self.user_cert, self.name)
        ):
            raise ValueError("Invalid client certificate")

    def process(self, message: bytes = b"") -> int | bytes:

        if message:
            print("receive message")
            message = Packet.from_json(message.decode())

            match message.type:
                case PacketType.SERVER_HELLO:
                    print("Received SERVER_HELLO")
                    server_cert = message.payload["certificade"]
                    server_cert_name = message.payload["certificade_name"]
                    server_nonce = message.payload["server_nonce"]

                    server_cert = base64.b64decode(server_cert)
                    server_nonce = base64.b64decode(server_nonce)
                    self.server_cert = load_pem_x509_certificate(server_cert)

                    if not self.certificate_validator.validate_certificate(
                        self.server_cert, server_cert_name
                    ):
                        print("Invalid server certificate")
                        return -1

                    server_nonce = self.private_key.decrypt(
                        server_nonce,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )
                    self.nonce = os.urandom(16)
                    nonce = self.server_cert.public_key().encrypt(
                        self.nonce,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )
                    print(f"client nonce: {nonce}")

                    signature = self.private_key.sign(
                        server_nonce,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )

                    message = create_client_auth(server_nonce, nonce, signature)
                    return message.to_json().encode()

                case PacketType.SERVER_AUTH:
                    print("Received SERVER_AUTH")
                    client_nonce = base64.b64decode(message.payload["client_nonce"])

                    encrypted_server_random = base64.b64decode(
                        message.payload["server_random"]
                    )

                    self.server_random = self.private_key.decrypt(
                        encrypted_server_random,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )

                    signature = base64.b64decode(message.payload["signature"])

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
                        print(f"Invalid signature: {e}")
                        return -1

                    if self.nonce != client_nonce:
                        print("Invalid nonce")
                        return -1

                    # Generate client random
                    self.client_random = os.urandom(32)

                    # Encrypt client random with server public key
                    encrypted_client_random = self.server_cert.public_key().encrypt(
                        self.client_random,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )

                    message = create_key_exchange(encrypted_client_random)
                    self.session_key = derive_keys(
                        self.client_random, self.server_random
                    )

                    return message.to_json().encode()

                case PacketType.CHANGE_CIPHER_SPEC:
                    print("Received CHANGE_CIPHER_SPEC")
                    cipher_spec = message.payload["change_spec"]

                    if cipher_spec != "AES-256-GCM":
                        print("Unsupported cipher spec")
                        return create_error().to_json().encode()

                    finish_message = create_finished(True)
                    return finish_message.to_json().encode()

                case PacketType.FINISH:
                    print("Received FINISH - Handshake complete")
                    print("Secure channel established!")

                    self.handshake_complete = True
                    message = ""
                    return self.process(message)

                case PacketType.DATA_EXCHANGE:
                    print("Received DATA_EXCHANGE")
                    encrypted_data = base64.b64decode(message.payload["data"])
                    iv = base64.b64decode(message.payload["iv"])
                    auth_tag = base64.b64decode(message.payload["auth_tag"])

                    try:
                        decrypted_data = decrypt_data(
                            encrypted_data, self.session_key, iv, auth_tag
                        )
                        print(f"Decrypted data: {decrypted_data.decode('utf-8')}")
                        return create_ack().to_json().encode()
                    except Exception as e:
                        print(f"Decryption error: {e}")
                        return create_error().to_json().encode()

                case PacketType.ACK:
                    return self.process(message="")

                case PacketType.ERROR:
                    print("Received ERROR")
                    return -1

                case _:
                    print("Unknown message type")
                    return -1
        else:
            if self.handshake_complete:
                message = input("Enter data to send: ")
                if message:
                    encrypted_data, iv, auth_tag = encrypt_data(
                        message.encode(), self.session_key
                    )
                    message = create_data_exchange(encrypted_data, iv, auth_tag)
                    return message.to_json().encode()
                return message.to_json().encode()
            else:
                print("No message received.")
                print("Sending CLIENT_HELLO")

                print(self.user_cert.public_key())

                message = create_client_hello(
                    self.user_cert.public_bytes(Encoding.PEM), self.name
                )
                return message.to_json().encode()

        return -1


async def tcp_sender(path_to_client_cert: str):
    reader, writer = await asyncio.open_connection(SERVER_HOST, SERVER_PORT)
    print(f"Connected to server at {SERVER_HOST}:{SERVER_PORT}")
    cliente = Client(path_to_client_cert)
    print(cliente)

    try:
        message = cliente.process()
        while message != -1:
            if message:
                writer.write(message)
                await writer.drain()  # Make sure data is sent
                data = await reader.read(MAX_MSG_SIZE)
                if not data:  # Check if server closed connection
                    print("Server closed connection")
                    break
                message = cliente.process(data)
            else:
                # If handshake is complete but no message to send right now
                if cliente.handshake_complete:
                    print(
                        "Handshake complete, enter data to send or wait for server data"
                    )
                    # Add interactive prompt or processing logic here
                    user_input = await asyncio.to_thread(
                        input,
                        "Enter message (or press Enter to wait for server data): ",
                    )
                    if user_input:
                        encrypted_data, iv, auth_tag = encrypt_data(
                            user_input.encode(), cliente.session_key
                        )
                        data_packet = create_data_exchange(encrypted_data, iv, auth_tag)
                        writer.write(data_packet.to_json().encode())
                        await writer.drain()

                    # Check for incoming data with a short timeout
                    try:
                        data = await asyncio.wait_for(
                            reader.read(MAX_MSG_SIZE), timeout=0.5
                        )
                        if data:
                            message = cliente.process(data)
                        else:
                            continue
                    except asyncio.TimeoutError:
                        continue
                else:
                    # Wait a bit and try again
                    await asyncio.sleep(0.1)
                    continue

        writer.write(b"\n")
        print("Socket closed")
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        print(f"Socket closed due to {e}!")
        writer.write(b"\n")
        writer.close()
        await writer.wait_closed()


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
        return asyncio.run(tcp_sender(client_cert_path))
    except KeyboardInterrupt:
        print("\nClient interrupted. Exiting...")
        return 0


if __name__ == "__main__":
    main(sys.argv[1:])

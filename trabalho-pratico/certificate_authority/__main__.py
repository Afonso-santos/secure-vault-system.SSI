import os
import sys
import argparse
import asyncio
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import asymmetric

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.Icarus_Protocol import *
from common.certificate_validator import CertificateValidator
from certificate_authority.certificates_generator import create_certificates


SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8888
MAX_MSG_SIZE = 8192


class CertificateAuthority:
    def __init__(self):
        self.name = "VAULT_CA"
        self.key_catalog = {}
        self.session_key = {}
        self.priv_key = None
        self.pub_key = None

        self.ca_certificate = None
        self.certificate_validator = None

    def set_ca_certificate(self, ca_certificate):
        """Set the CA certificate."""
        self.ca_certificate = ca_certificate
        self.pub_key = ca_certificate.public_key()
        self.certificate_validator = CertificateValidator(ca_certificate)

    def set_priv_key(self, priv_key):
        """Set the private key."""
        self.priv_key = priv_key

    def add_key(self, name: str, key):
        """Add a key to the catalog."""
        if name in self.key_catalog:
            raise ValueError(f"Key with name {name} already exists.")
        self.key_catalog[name] = key
        print(f"Key {name} added to the catalog.")

    def get_key(self, name: str):
        """Get a key from the catalog."""
        if name not in self.key_catalog:
            raise ValueError(f"Key with name {name} does not exist.")
        return self.key_catalog[name]

    def process(self, message: bytes = b"", client_id=None) -> int | bytes:
        """Process incoming data and return a response."""

        # Store client state using client_id
        if client_id and client_id not in self.session_key:
            self.session_key[client_id] = {
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
                    print("Client Hello received")
                    client_cert = message.payload["certificate"]
                    client_cert_name = message.payload["certificate_name"]
                    client_cert = base64.b64decode(client_cert)
                    client_cert = load_pem_x509_certificate(client_cert)

                    if not self.certificate_validator.validate_certificate(
                        client_cert, client_cert_name
                    ):
                        print("Invalid client certificate")
                        return -1

                    client_state["client_cert"] = client_cert

                    nonce = os.urandom(16)
                    encrypt_nonce = client_cert.public_key().encrypt(
                        nonce,
                        asymmetric.padding.OAEP(
                            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )
                    client_state["nonce"] = nonce
                    client_state["time_stamp"] = datetime.now(timezone.utc).timestamp()

                    self.session_key[client_id] = client_state

                    server_hello_packet = create_server_hello(
                        self.name,
                        self.ca_certificate.public_bytes(serialization.Encoding.PEM),
                        encrypt_nonce,
                    )
                    return server_hello_packet.to_json().encode()

                case PacketType.CLIENT_AUTH:

                    client_nonce = message.payload["client_nonce"]
                    server_nonce = message.payload["server_nonce"]
                    signature = message.payload["signature"]

                    client_nonce = base64.b64decode(client_nonce)
                    server_nonce = base64.b64decode(server_nonce)
                    signature = base64.b64decode(signature)

                    client_cert = client_state.get("client_cert")
                    if not client_cert:
                        print("Client certificate not found")
                        return -1

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
                        print(f"Signature verification failed: {e}")
                        return -1

                    client_nonce = self.priv_key.decrypt(
                        client_nonce,
                        asymmetric.padding.OAEP(
                            mgf=asymmetric.padding.MGF1(hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )

                    signature = self.priv_key.sign(
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
                        > datetime.now(timezone.utc).timestamp()
                    ):
                        print("Invalid nonce or expired timestamp")
                        return -1

                    client_state["nonce"] = None
                    client_state["time_stamp"] = None

                    server_random = os.urandom(16)
                    client_state["server_random"] = server_random
                    self.session_key[client_id] = client_state

                    server_auth_packet = create_server_auth(
                        client_nonce,
                        server_random,
                        signature,
                    )

                    return server_auth_packet.to_json().encode()

                case PacketType.KEY_EXCHANGE:
                    client_random = message.payload["client_random"]
                    client_random = base64.b64decode(client_random)

                    client_state["client_random"] = client_random

                    session_key = derive_keys(
                        client_random,
                        client_state["server_random"],
                    )

                    client_state["key"] = session_key
                    self.session_key[client_id] = client_state

                    change_cipher_spec_packet = create_change_cipher_spec("AES-256-GCM")
                    return change_cipher_spec_packet.to_json().encode()

                case PacketType.FINISH:

                    finish_data = message.payload.get("change_spec", "")

                    client_state["handshake_complete"] = True
                    self.session_key[client_id] = client_state

                    finish_packet = create_finished(True)
                    return finish_packet.to_json().encode()
                case PacketType.DATA_EXCHANGE:
                    print("Received DATA_EXCHANGE")

                    if not client_state.get("handshake_complete", False):
                        print("Received data before handshake completion")
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
                        print(f"Base64 decoding error: {e}")
                        return create_error().to_json().encode()

                    try:
                        decrypted_data = decrypt_data(
                            encrypted_data, client_state["key"], iv, auth_tag
                        )
                        print(f"Decrypted data: {decrypted_data.decode('utf-8')}")

                        response_data = decrypted_data.decode("utf-8").upper()
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

                case _:
                    print(f"Unknown message type: {message.type}")
                    return create_error().to_json().encode()

        return -1

    def save_to_disk(self, path):
        # Create directory if it doesn't exist
        os.makedirs(path, exist_ok=True)

        # Save CA certificate
        with open(f"{path}/ca_cert.pem", "wb") as f:
            f.write(self.ca_certificate.public_bytes(serialization.Encoding.PEM))

        # Save CA private key
        with open(f"{path}/ca_key.pem", "wb") as f:
            f.write(
                self.priv_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )

        # Save key catalog - serialize public keys to PEM format
        serialized_catalog = {}
        for name, key in self.key_catalog.items():
            serialized_catalog[name] = key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )

        with open(f"{path}/key_catalog.json", "w") as f:
            json.dump(
                {name: key.decode("utf-8") for name, key in serialized_catalog.items()},
                f,
            )

    def load_from_disk(self, path):
        # Load CA certificate
        with open(f"{path}/ca_cert.pem", "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
            self.set_ca_certificate(ca_cert)

        # Load CA private key
        with open(f"{path}/ca_key.pem", "rb") as f:
            priv_key = serialization.load_pem_private_key(f.read(), password=None)
            self.set_priv_key(priv_key)

        # Load key catalog
        with open(f"{path}/key_catalog.json", "r") as f:
            serialized_catalog = json.load(f)

        # Deserialize public keys from PEM format
        self.key_catalog = {}
        for name, pem_key in serialized_catalog.items():
            self.key_catalog[name] = serialization.load_pem_public_key(
                pem_key.encode("utf-8")
            )


async def handle_echo(reader, writer, cert_autority: CertificateAuthority):
    addr = writer.get_extra_info("socket")
    client_id = id(writer)
    """Handle incoming connections and echo messages back to the client."""
    while True:
        try:
            data = await reader.read(MAX_MSG_SIZE)
            if not data:
                break
            response = cert_autority.process(data, client_id)
            if response == -1:
                print("Invalid message received")
                break

            if response:
                writer.write(response)
                await writer.drain()
        except Exception as e:
            print(f"Error: {e}")
            break
    # Close the connection
    print("Closing the connection")
    writer.write(b"Connection closed")
    await writer.drain()

    print("Closing the connection")
    writer.close()
    await writer.wait_closed()


def run_ca_server(cert_autority: CertificateAuthority):
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(
        lambda r, w: handle_echo(r, w, cert_autority), SERVER_HOST, SERVER_PORT
    )
    ca_server = loop.run_until_complete(coro)
    print(f"Serving on {SERVER_HOST}:{SERVER_PORT}")
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("Server stopped.")
    finally:
        ca_server.close()
        loop.run_until_complete(ca_server.wait_closed())
        loop.close()


def main():
    cert_authority = CertificateAuthority()

    parser = argparse.ArgumentParser(
        description="Certificate Authority Management Tool"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Create command
    create_parser = subparsers.add_parser("create", help="Create certificates")
    create_parser.add_argument(
        "-s",
        "--server",
        type=int,
        required=True,
        help="Number of server certificates to create",
    )
    create_parser.add_argument(
        "-c",
        "--client",
        type=int,
        required=True,
        help="Number of client certificates to create",
    )
    create_parser.add_argument(
        "-o", "--output", required=True, help="Output directory for certificates"
    )

    # Run command
    run_parser = subparsers.add_parser("run", help="Run CA server")
    run_parser.add_argument(
        "-d",
        "--directory",
        required=True,
        help="Directory with CA certificate and key catalog",
    )

    args = parser.parse_args()

    if args.command == "create":
        # Creator mode
        dic_cert = create_certificates(args.output, args.server, args.client)

        cert_authority.set_ca_certificate(dic_cert["ca_cert"])
        cert_authority.set_priv_key(dic_cert["ca_key"])

        for client_cert in dic_cert["client_certs"]:
            cert_authority.add_key(
                client_cert.subject.get_attributes_for_oid(x509.NameOID.PSEUDONYM)[
                    0
                ].value,
                client_cert.public_key(),
            )

        for server_cert in dic_cert["server_certs"]:
            cert_authority.add_key(
                server_cert.subject.get_attributes_for_oid(x509.NameOID.PSEUDONYM)[
                    0
                ].value,
                server_cert.public_key(),
            )

        # Save CA state to disk
        cert_authority.save_to_disk(args.output)

        print("CA catalog")
        for name, key in cert_authority.key_catalog.items():
            print(f"Name: {name}, Key: {key}")
        print("." * 60)
        print(f"CA certificates and key catalog saved to {args.output}")

    elif args.command == "run":
        # Runner mode
        print(f"Loading CA state from {args.directory}...")
        cert_authority.load_from_disk(args.directory)

        print("Loaded CA catalog:")
        for name, _ in cert_authority.key_catalog.items():
            print(f"Name: {name}")
        print("." * 60)

        print("Running the CA server...")
        try:
            run_ca_server(cert_authority)
        except KeyboardInterrupt:
            print("Server stopped.")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

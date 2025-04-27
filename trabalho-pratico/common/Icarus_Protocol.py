import os
import enum
import json
import base64
from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


class PacketType(enum.Enum):
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    KEY_EXCHANGE = 3
    CLIENT_AUTH = 4
    SERVER_AUTH = 5
    CHANGE_CIPHER_SPEC = 6
    FINISH = 7
    DATA_EXCHANGE = 8

    ACK = 9
    ERROR = 10

    GET = 11


class Packet:
    def __init__(self, packet_type: PacketType, payload):
        self.type = packet_type
        self.payload = payload

    def to_json(self):
        return json.dumps({"type": self.type.name, "payload": self.payload})

    @staticmethod
    def from_json(json_str: str):
        data = json.loads(json_str)
        packet_type = PacketType[data["type"]]
        payload = data["payload"]
        return Packet(packet_type, payload)


def create_packet(packet_type: PacketType, payload) -> Packet:
    packet = Packet(packet_type, payload)
    return packet


def create_client_hello(cert: bytes, cert_name: str) -> Packet:
    """Create a CLIENT_HELLO packet"""
    payload = {
        "certificate": base64.b64encode(cert).decode("utf-8"),
        "certificade_name": cert_name,
    }
    return create_packet(PacketType.CLIENT_HELLO, payload)


def create_server_hello(cert_name: str, cert: bytes, nonce: bytes) -> Packet:
    """Create a SERVER_HELLO packet"""
    payload = {
        "certificade_name": cert_name,
        "certificade": base64.b64encode(cert).decode("utf-8"),
        "server_nonce": base64.b64encode(nonce).decode("utf-8"),
    }
    return create_packet(PacketType.SERVER_HELLO, payload)


def create_client_auth(
    server_nonce: bytes, client_nonce: bytes, signature: bytes
) -> Packet:
    """Create a CLIENT_AUTH packet"""
    payload = {
        "server_nonce": base64.b64encode(server_nonce).decode("utf-8"),
        "client_nonce": base64.b64encode(client_nonce).decode("utf-8"),
        "signature": base64.b64encode(signature).decode("utf-8"),
    }
    return create_packet(PacketType.CLIENT_AUTH, payload)


def create_server_auth(
    client_nonce: bytes, server_random: bytes, signature: bytes
) -> Packet:
    """Create a SERVER_AUTH packet"""
    payload = {
        "client_nonce": base64.b64encode(client_nonce).decode("utf-8"),
        "server_random": base64.b64encode(server_random).decode("utf-8"),
        "signature": base64.b64encode(signature).decode("utf-8"),
    }
    return create_packet(PacketType.SERVER_AUTH, payload)


def create_key_exchange(client_random: bytes) -> Packet:
    """Create a KEY_EXCHANGE packet"""
    payload = {
        "client_random": base64.b64encode(client_random).decode("utf-8"),
    }
    return create_packet(PacketType.KEY_EXCHANGE, payload)


def create_change_cipher_spec(cipher: str) -> Packet:
    """Create a CHANGE_CIPHER_SPEC packet"""
    payload = {"change_spec": cipher}
    return create_packet(PacketType.CHANGE_CIPHER_SPEC, payload)


def create_finished(resp: bool) -> Packet:
    """Create a FINISH packet"""
    # Convert boolean to bytes before base64 encoding
    resp_bytes = b"1" if resp else b"0"
    payload = {"change_spec": base64.b64encode(resp_bytes).decode("utf-8")}
    return create_packet(PacketType.FINISH, payload)


def create_data_exchange(encrypted_data: bytes, iv: bytes, auth_tag: bytes) -> Packet:
    """Create a DATA_EXCHANGE packet with encrypted payload"""
    payload = {
        "data": base64.b64encode(encrypted_data).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "auth_tag": base64.b64encode(auth_tag).decode("utf-8"),
    }
    return create_packet(PacketType.DATA_EXCHANGE, payload)


def create_ack() -> Packet:
    """Create an ACK packet"""
    payload = {}
    return create_packet(PacketType.ACK, payload)


def create_get(id: str, command: str, key=None) -> Packet:
    """Create a GET packet"""
    if key is isinstance(key, bytes):
        key = base64.b64encode(key).decode("utf-8")

    payload = {
        "id": id,
        "key": key,
        "command": command,
    }
    return create_packet(PacketType.GET, payload)


def create_error() -> Packet:
    """Create an ERROR packet"""
    payload = {}
    return create_packet(PacketType.ERROR, payload)


def encrypt_data(
    data: bytes, key: bytes, iv: bytes = None
) -> Tuple[bytes, bytes, bytes]:
    """Encrypt data using AES-GCM"""
    if iv is None:
        iv = os.urandom(12)  # GCM recommended IV length

    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()

    ciphertext = encryptor.update(data) + encryptor.finalize()

    return ciphertext, iv, encryptor.tag


def decrypt_data(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
    """Decrypt data using AES-GCM"""
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()


def derive_keys(client_random: bytes, server_random: bytes) -> bytes:
    """Derive various session keys from shared secret"""
    key_material = client_random + server_random

    # Use HKDF to derive multiple keys
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # We'll slice this for different keys
        salt=None,
        info=b"icarus_protocol_key_derivation",
    )

    key = hkdf.derive(key_material)

    return key

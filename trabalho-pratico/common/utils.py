import os
import json

from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509


def get_userdata(p12_fname):
    with open(p12_fname, "rb") as f:
        p12 = f.read()
    password = None  # p12 não está protegido...

    # Extract the name from the filename (remove path and extension)
    name = os.path.basename(p12_fname).split(".")[0]

    private_key, user_cert, ca_certs = pkcs12.load_key_and_certificates(p12, password)
    # ca_cert will be the first certificate in ca_certs if available
    ca_cert = ca_certs[0] if ca_certs else None
    return (name, private_key, user_cert, ca_cert)


def sign_data(data: bytes, key) -> bytes:
    """Sign data using a private key object"""
    if isinstance(key, rsa.RSAPrivateKey):
        signature = key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
    else:
        raise ValueError("Unsupported key type")

    return signature


def verify_signature(data: bytes, signature: bytes, key: rsa.RSAPublicKey) -> bool:
    """
    Verify the signature of a file using the public key.
    """
    try:
        key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False


def encrypt_file(plaintext: str, key=None) -> tuple:
    """Encrypt a file using AES encryption"""
    if key is None:
        key = os.urandom(32)  # Generate a random 256-bit key

    # Generate a random IV
    iv = os.urandom(16)

    # Create AES cipher
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()

    # Encrypt the data
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return iv + ciphertext, key  # Return both the encrypted data (with IV) and the key


def decrypt_file(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt a file using AES encryption"""
    # Extract the IV from the beginning of the data
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    # Create AES cipher
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()

    # Decrypt the data
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext


def hash_file(data_str: str) -> bytes:
    """Hash a file using SHA-256"""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data_str)
    return digest.finalize()


def encrypt_key(file_key, client_key) -> bytes:
    """Encrypt a key using RSA public key"""
    if isinstance(client_key, bytes):
        client_key = serialization.load_pem_public_key(client_key)
    # Assume it's already a key object

    cipherkey = client_key.encrypt(
        file_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return cipherkey


def decrypt_key(encrypted_key: bytes, rsa_key: bytes) -> bytes:
    """Decrypt a key using RSA private key"""
    private_key = serialization.load_pem_private_key(rsa_key, password=None)
    plaintext = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext


def dict_to_json(data: dict) -> str:
    """Convert a dictionary to a JSON string"""
    return json.dumps(data)


def json_to_dict(json_str: str) -> dict:
    """Convert a JSON string to a dictionary"""
    return json.loads(json_str)

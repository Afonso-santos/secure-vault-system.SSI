import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa

from common.utils import verify_signature, decrypt_file


def pprint_add(payload: dict) -> None:
    """
    Pretty print the add command response
    """
    print("📄 File added successfully")
    print(f"File ID: {payload['file_id']}")
    print("------------------------------")


def pprint_details(payload: dict) -> None:
    """
    Pretty print the details command response
    """
    print("🖊️ File details:")
    print(f"File ID: {payload['file_id']}")
    print(f"File name: {payload['file_name']}")
    print(f"File Owner: {payload['file_owner']}")
    print(
        f"File creation date: {payload['create_at'][:10]} at {payload['create_at'][11:19]}"
    )
    print(
        f"File last modified date: {payload['modified_at'][:10]} at {payload['modified_at'][11:19]} by: {payload['by']}"
    )
    print(f"People with access: {chr(10).join(payload['listed_users'])}")
    print("------------------------------")


def pprint_read(client, payload: dict) -> None:
    """
    Pretty print the read command response and decrypt the file
    """
    # Decode the payload items
    encrypted_key = base64.b64decode(payload["key"])
    file_hash = base64.b64decode(payload["file_hash"])
    signature = base64.b64decode(payload["signature"])
    ciphertext = base64.b64decode(payload["content"])

    print(f"🔑 Received encrypted file data")

    # Decrypt the AES key using client's private key
    key = client.private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Optional: Verify the signature
    try:
        client.public_key.verify(
            signature,
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        print("✅ Signature verification successful")
    except Exception as e:
        print(f"❌ Signature verification failed: {e}")

    # Decrypt the file content
    plaintext = decrypt_file(ciphertext, key)

    print("📄 File content:")
    print(plaintext.decode("utf-8"))
    print("------------------------------")

    return plaintext

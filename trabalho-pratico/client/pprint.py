import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa

from common.utils import verify_signature, decrypt_file, json_to_dict


def pprint_add(payload: dict) -> None:
    """
    Pretty print the add command response
    """
    print("📄 File added successfully")
    print(f"File ID: {payload['file_id']}")
    print("------------------------------")


def pprint_group_create(payload: dict) -> None:
    """
    Pretty print the group create command response
    """
    print("👥 Group created successfully")
    print(f"Group ID: {payload['group_id']}")
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


def pprint_read(client, payload: dict, public_key) -> None:
    """Pretty print the read command response and decrypt the file"""
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
        if public_key:
            pubkey_obj = serialization.load_pem_public_key(public_key.encode())

        else:
            pubkey_obj = client.public_key

        pubkey_obj.verify(
            signature,
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        print("✅ Signature verification successful")

    except Exception as e:
        print(f"❌ Signature verification failed: {e}")

    # Decrypt the file content
    plaintext = decrypt_file(ciphertext, key)
    # Try to decode as UTF-8, but handle binary data gracefully

    decoded_content = plaintext.decode()
    print("📄 File content:")
    print(decoded_content)

    print("------------------------------")


def pprint_replace(msg: str) -> None:
    """
    Pretty print the replace command response
    """
    print("📄" + msg)
    print("------------------------------")


def pprint_group_delete(payload: dict) -> None:
    """
    Pretty print the group delete command response
    """
    print("👥 Group deleted successfully")
    print(f"👥 {payload['msg']}")
    print("------------------------------")


def pprint_delete_file(payload: dict) -> None:
    """
    Pretty print the delete file command response
    """
    print("📄 File deleted successfully")
    print(f"📄 {payload['msg']}")
    print("------------------------------")


def pprint_group_add_user(payload: dict) -> None:
    """
    Pretty print the group add user command response
    """
    print("👥 User added to group successfully")
    print(f"👥 {payload['msg']}")
    print("------------------------------")


def pprint_share(payload: dict) -> None:
    """
    Pretty print the share command response
    """
    print("📄 File shared successfully")
    print(f"Permissions: {payload['msg']}")
    print("------------------------------")


def pprint_group_add_file(payload: dict) -> None:
    """
    Pretty print the group add file command response
    """
    print("👥 📄 File added to group successfully")
    print(f"File ID: {payload['file_id']}")
    print("------------------------------")

def pprint_group_list(payload: dict) -> None:
    """
    Pretty print the group list command response
    """
    dict_groups = payload["dict_groups"]
    dict_groups = json_to_dict(dict_groups)

    print("👥 Group list:")
    for group_id, group_info in dict_groups.items():
        print(f"📁 Group ID: {group_id}")
        print(f"   📌 Name       : {group_info.get('group_name', 'N/A')}")
        print(f"   🛡️ Permissions: {', '.join(group_info.get('permissions', []))}")
        print(f"   👑 Is Owner   : {group_info.get('is_owner', False)}\n")

def pprint_revoke_file(payload: dict) -> None:
    """
    Pretty print the revoke file command response
    """
    print("📄 File revoked successfully")
    print(f"File ID: {payload['msg']}")
    print("------------------------------")

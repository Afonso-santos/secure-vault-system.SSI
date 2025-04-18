import os


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


def sign_data(data: bytes, private_key_pem: bytes) -> bytes:
    """Sign data using private key"""
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    if isinstance(private_key, rsa.RSAPrivateKey):
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError("Unsupported key type")

    return signature

import os, sys
import cryptography.hazmat.primitives.ciphers.algorithms as algorithms
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.padding import PKCS7

BLOCK_SIZE = 128

def setup(fkey:str) -> None:
    key = os.urandom(32)
    with open(fkey, "wb") as f:
        f.write(key)
    
def enc(fich:str, fkey:str) -> None:
    with open(fkey, "rb") as f:
        key = f.read()

    with open(fich, "rb") as f:
        plaintext = f.read()

    padder = PKCS7(BLOCK_SIZE).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    iv = os.urandom(16)
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=CBC(iv))

    ciphertext = cipher.encryptor().update(padded_plaintext)+cipher.encryptor().finalize()

    with open(fich + ".enc", "wb") as f: 
        f.write(iv)
        f.write(ciphertext)


def dec(fich:str, fkey:str) -> None:
    with open(fkey, "rb") as f:
        key = f.read()
    
    with open(fich, "rb") as f:
        iv = f.read(16)
        ciphertext = f.read()
    
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=CBC(iv))
    decrypted = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()

    unpadder = PKCS7(BLOCK_SIZE).unpadder()
    plaintext = unpadder.update(decrypted) + unpadder.finalize()

    with open(fich + ".dec", "wb") as f:
        f.write(plaintext)

def main() -> None:
    func = sys.argv[1]
    
    if func=="setup":
        fkey = sys.argv[2]

        setup(fkey)

    elif func =="enc":
        fich = sys.argv[2]
        fkey = sys.argv[3]

        enc(fich, fkey)

    elif func=="dec":
        fich = sys.argv[2]
        fkey = sys.argv[3]

        dec(fich, fkey)

    else:
        print("Invalid function")
        sys.exit(1)

if __name__ == "__main__":
    main()
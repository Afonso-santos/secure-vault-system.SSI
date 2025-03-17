import os, struct, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def KeyDerivation(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return kdf.derive(password.encode())

def enc(fich: str) -> None:
    with open(fich, "rb") as f:
        plaintext = f.read()

    password = input("Password: ")
    
    salt = os.urandom(16)  
    key = KeyDerivation(password, salt)
    nonce = os.urandom(16)
    algorithm = AESGCM(key)

    ciphertext = algorithm.encrypt(nonce, plaintext, None)

    with open(fich + ".enc", "wb") as f:
        f.write(salt)  
        f.write(nonce)
        f.write(ciphertext)
       

def dec(fich:str) -> None:
    password = input("Password: ")

    with open(fich, "rb") as f:
        salt = f.read(16)  
        nonce = f.read(16) 
        ciphertext = f.read()

    key = KeyDerivation(password, salt)
    algorithm = AESGCM(key)
    plaintext = algorithm.decrypt(nonce, ciphertext, None)

    with open(fich + ".dec", "wb") as f:
        f.write(plaintext)

def main() -> None:

    if len(sys.argv) < 3:
        print("Uso: python pbenc_chacha20.py <enc/dec> <ficheiro>")
        sys.exit(1)

    func = sys.argv[1]
    fich = sys.argv[2]

    if func == "enc":
        enc(fich)
    elif func == "dec":
        dec(fich)
    else:
        print("Função inválida. Use 'enc' para cifrar ou 'dec' para decifrar.")
        sys.exit(1)

if __name__ == "__main__":
    main()

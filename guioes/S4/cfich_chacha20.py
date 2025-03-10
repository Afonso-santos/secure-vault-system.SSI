from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
import sys
import os

def setup(fkey: str) -> bool:
    # Key generation (32 random bytes)
    key = os.urandom(32)
    # Save to file
    with open(fkey, "wb") as f:
        f.write(key)
    return True

def encrypt(file: str, fkey: str) -> bool:
    # Read key from file
    with open(fkey, "rb") as f:
        key = f.read()
    
    # Read file to encrypt
    with open(file, "rb") as f:
        data = f.read()

    # Nonce generation (16 random bytes)
    nonce = os.urandom(16)

    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()

    ct = encryptor.update(data) + encryptor.finalize()

    # Save encrypted data to file
    with open(file + ".enc", "wb") as f:
        f.write(ct + nonce)

    return True

def decrypt(file: str, fkey: str) -> bool:
    # Read key from file
    with open(fkey, "rb") as f:
        key = f.read()
    
    # Read file to decrypt
    with open(file, "rb") as f:
        data = f.read()

    # Read nonce (last 16 bytes of the encrypted file)
    nonce = data[-16:]

    # Read content (all except nonce)
    ct = data[:-16]

    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()

    pt = decryptor.update(ct) + decryptor.finalize()

    # Save decrypted data to file
    with open(file + ".dec", "wb") as f:
        f.write(pt)

    return True

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: cfich_chacha20.py <operation>")
        sys.exit(1)
    
    operation = sys.argv[1]

    match operation:
        case "setup":
            if len(sys.argv) < 3:
                print("Usage: cfich_chacha20.py setup <fkey>")
                sys.exit(1)
            
            fkey = sys.argv[2]
            if setup(fkey):
                print("Key generated and saved to file " + fkey + " successfully.")
            else:
                print("Error generating key")
                sys.exit(1)
        case "enc":
            if len(sys.argv) < 4:
                print("Usage: cfich_chacha20.py enc <fich> <fkey>")
                sys.exit(1)

            file = sys.argv[2]
            fkey = sys.argv[3]

            if encrypt(file, fkey):
                print("File " + file + " encrypted successfully. (saved to " + file + ".enc)")
            else:
                print("Error encrypting file")
                sys.exit(1)
        case "dec":
            if len(sys.argv) < 4:
                print("Usage: cfich_chacha20.py dec <fich> <fkey>")
                sys.exit(1)

            file = sys.argv[2]
            fkey = sys.argv[3]

            if decrypt(file, fkey):
                print("File " + file + " decrypted successfully. (saved to " + file + ".dec)")
            else:
                print("Error decrypting file")
                sys.exit(1)
        case _:
            print("Invalid operation")
            sys.exit(1)

if __name__ == "__main__":
    main()
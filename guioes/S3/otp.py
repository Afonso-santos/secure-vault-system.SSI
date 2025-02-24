import sys
import os

def setup(file_name: str, nbytes:int) -> None:
    with open(file_name,"wb") as f:
        f.write(os.urandom(nbytes))

def enc(plaintext_file: str, key_file: str) -> None:

    with open(plaintext_file, "rb") as f:
        plaintext = f.read()
    with open(key_file, "rb") as f:
        key = f.read()

    ciphertext = bytes([p^k for p,k in zip(plaintext, key)])
    with open(plaintext_file + ".enc", "wb") as f:
        f.write(ciphertext)

def dec(ciphertext_file: str, key_file: str) -> None:
    
    with open(ciphertext_file, "rb") as f:
        ciphertext = f.read()
    with open(key_file, "rb") as f:
        key = f.read()

    plaintext = bytes([c^k for c,k in zip(ciphertext, key)])
    with open(ciphertext_file + ".dec", "wb") as f:
        f.write(plaintext)


def main() -> None:
    task = sys.argv[1]
    arg1 = sys.argv[2]
    arg2 = sys.argv[3]

    if task =="setup": 
        nbytes = int(sys.argv[2])
        file_name = sys.argv[3]
        setup(file_name, nbytes)

    elif task =="enc":
        plaintext_file = arg1
        key_file= arg2
        enc(plaintext_file, key_file)
        
    elif task =="dec":
        ciphertext_file = arg1
        key_file = arg2
        dec(ciphertext_file, key_file)
    
    else:
        print("Usage: python3 otp.py <setup||enc||dec> <key> <message>")
        sys.exit(1)

if __name__ == "__main__":
    main()
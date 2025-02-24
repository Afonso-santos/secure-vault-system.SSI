import sys

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def preproc(message:str) -> str:
    l = []
    for c in message:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)


def encrypt(key:int, message:str)->str:
    encrypted = ""
    for c in message:
        if c.isalpha():
            ascii = ord(c)
            encrypted += chr((ascii + key - 65) % 26 + 65)
        else:
            encrypted += c
    return encrypted

def decrypt(key:int, message:str)->str:
    decrypted = ""
    for c in message:
        if c.isalpha():
            ascii = ord(c)
            decrypted += chr((ascii - key - 65) % 26 + 65)
        else:
            decrypted += c
    return decrypted


def main()->None:

    if len(sys.argv) != 4:
        print("Usage: python cesar.py <enc||dec> <key> <message>")
        sys.exit(1)
    
    func = sys.argv[1]
    key = alphabet.index(sys.argv[2].upper())
    message = sys.argv[3]
    message = preproc(message)

    
    if func == "enc":
        encrypted = encrypt(key, message)
        print(encrypted)
    elif func == "dec":
        decrypted = decrypt(key ,message)
        print(decrypted)
    else:
        print("Usage: python cesar.py <enc||dec> <key> <message>")
        sys.exit(1)


    

if __name__ == "__main__":
    main()
import sys

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def preproc(message:str) -> str:
    l = []
    for c in message:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)


def encrypt(key: list[int], message: str) -> str:
    encrypted = []
    key_length = len(key)
    
    for i, c in enumerate(message):
        if c.isalpha():
            shift = key[i % key_length]  
            base = 65 if c.isupper() else 97  
            encrypted.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            encrypted.append(c)  
    
    return "".join(encrypted)


def decrypt(key: list[int], message: str) -> str:
    decrypted = []
    key_length = len(key)

    for i, c in enumerate(message):
        if c.isalpha():  
            shift = key[i % key_length]  
            base = 65 if c.isupper() else 97  
            
            decrypted.append(chr((ord(c) - base - shift) % 26 + base))   
        else:
            decrypted.append(c)  

    return "".join(decrypted)

def main() -> None:
    key_list = []
    if len(sys.argv) != 4:
        print("Usage: python cesar.py <enc||dec> <key word> <message>")
        sys.exit(1)
    
    func = sys.argv[1]
    key_word = preproc(sys.argv[2])   
    key_list=[alphabet.index(c) for c in key_word]
    message = sys.argv[3]
    message = preproc(message)

    
    if func == "enc":
        encrypted = encrypt(key_list, message)
        print(encrypted)
    elif func == "dec":
        decrypted = decrypt(key_list ,message)
        print(decrypted)
    else:
        print("Usage: python cesar.py <enc||dec> <key> <message>")
        sys.exit(1)


    

if __name__ == "__main__":
    main()
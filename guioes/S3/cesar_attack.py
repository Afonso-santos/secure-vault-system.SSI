import sys

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def preproc(message:str) -> str:
    l = []
    for c in message:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)


def decrypt(key:int, message:str)->str:
    decrypted = ""
    for c in message:
        if c.isalpha():
            ascii = ord(c)
            decrypted += chr((ascii - key - 65) % 26 + 65)
        else:
            decrypted += c
    return decrypted

def brute_force(message:str, wordlist:list)->tuple:
    for key in range(26):
        decrypted = decrypt(key, message)
        for word in wordlist:
            if word in decrypted:
                return alphabet[key], decrypted
    return None, None


def main()->None:
    wordlist = []
    if len(sys.argv) != 4:
        print("Usage: python cesar.py <message> <wordlist>")
        sys.exit(1)
   
    message = preproc(sys.argv[1])
    for word in sys.argv[2:]:
        wordlist.append(preproc(word))

    key, decrypted = brute_force(message, wordlist)

    if key is None:
        return 
    else:
        print(f"Key: {key}")
        print(f"Decrypted: {decrypted}")


if __name__ == "__main__":
    main()
import sys

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
portuguese_frequencies = {
    'a': 0.1463, 'b': 0.0104, 'c': 0.0388, 'd': 0.0499, 'e': 0.1257, 'f': 0.0102, 'g': 0.0130, 
    'h': 0.0128, 'i': 0.0618, 'j': 0.0040, 'k': 0.0002, 'l': 0.0278, 'm': 0.0474, 'n': 0.0505, 
    'o': 0.1073, 'p': 0.0252, 'q': 0.0120, 'r': 0.0653, 's': 0.0781, 't': 0.0434, 'u': 0.0463, 
    'v': 0.0167, 'w': 0.0001, 'x': 0.0021, 'y': 0.0001, 'z': 0.0047
}

def preproc(message:str) -> str:
    l = []
    for c in message:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)

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

def divide_in_groups(groups:list,key_len:int, message:str)->list:
   for i in range(key_len):
       groups.append(message[i::key_len])
   return groups
    

def concatenate(groups:list)->str:
    return "".join(groups)

def freq_analysis(sequence: str) -> str:
    all_chi_squareds = [0] * 26

    for i in range (26):
        chi_squared_sum = 0.0
        sequence_offset = [chr(((ord(sequence[j]) - 65 - i) % 26) + 65) for j in range(len(sequence))]
        v={letter:0 for letter in alphabet}

        for l in sequence_offset:
            v[l] += 1

        total = len(sequence)
        for letter in v:
            v[letter] /= total
        
        for letter in v:
            excepted = portuguese_frequencies.get(letter.lower(), 0.0001)
            chi_squared_sum += ((v[letter]-excepted)**2) / excepted
        
        all_chi_squareds[i] = chi_squared_sum


    shift = all_chi_squareds.index(min(all_chi_squareds))
    return chr(shift +65)

def attack(key_len: int, key_word: str, wordlist: list) -> tuple:
    groups = []
    divide_in_groups(groups, key_len, key_word)

    key = ""
    for i in range(key_len):
        key += freq_analysis(groups[i]) 

    key_list = [alphabet.index(c) for c in key]  
    plaintext = decrypt(key_list, key_word)  

    for word in wordlist:
        if word in plaintext:
            return key ,plaintext    

    return None, None

def main() -> None:
    wordlist = []
    if len(sys.argv) < 4:
        print("Usage: python3 vigenere_attack.py <key length> <key word> <wordlist>")
        sys.exit(1)
    
    key_len = int(sys.argv[1])
    key_word = preproc(sys.argv[2]) 

    for word in sys.argv[3:]:
        wordlist.append(preproc(word))
    
    key , decrypted = attack(key_len, key_word, wordlist)

    if key != None:
        print(key)
        print(decrypted)
        

    

if __name__ == "__main__":
    main()
import sys

def sub_cipher_text(nonce: bytes, cipher_text: bytes, start_position: int, known_word: str ,new_word:str ) -> bytes:
    cipher_text_mutable = bytearray(cipher_text) 

    for i in range(start_position, start_position + len(known_word)):
        cipher_text_mutable[i] ^= ord(known_word[i - start_position]) ^ ord(new_word[i - start_position])

    return bytes(cipher_text_mutable)


def attack(cipher_file: str, start_position: int, known_word: str, new_word: str) -> None:
    with open(cipher_file, "rb") as f:
        nonce = f.read(16)
        cipher_text = f.read()

    cipher_text_crack = sub_cipher_text(nonce, cipher_text, start_position, known_word, new_word)


    with open(cipher_file + ".attck", "wb") as f:
        f.write(nonce)
        f.write(cipher_text_crack)

    print("Attack successful")

    return None

def main() -> None:
    if len(sys.argv) < 5:
        print("Usage: chacha20_int_attck.py <fctxt> <start_position> <known_word> <new_word>")

    cipher_file = sys.argv[1]
    start_position = int(sys.argv[2])
    known_word = sys.argv[3]
    new_word = sys.argv[4]

    attack(cipher_file, start_position, known_word, new_word)
    
    return None

if __name__ == "__main__":
    main()
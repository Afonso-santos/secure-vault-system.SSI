import sys
import random


def attack(ciphertext_file: str, wordlist: list) -> str:
    with open(ciphertext_file, "rb") as f:
        ciphertext = f.read()

    for i in range(pow(2,16)):
        random.seed(i.to_bytes(2, "big"))
        key = random.randbytes(len(ciphertext))
        plaintext = bytes([c^k for c,k in zip(ciphertext, key)])

        for word in wordlist:
            if word.encode() in plaintext:
                return plaintext


def main() -> None:
    ciphertext_file = sys.argv[1]
    wordlist = sys.argv[2:]

    plain_text = attack(ciphertext_file, wordlist)

    print(plain_text)


if __name__ == "__main__":
    main()
import typer
from pydantic import BaseModel


"""
    Affine Cipher
    Encrypts, Decrpyts, and Deciphers a text file.
    Uses typer for command line parsing.
    Uses Pydantic to create Key Pair Objects.
    
    To run program
    In command line run:
    Note: Include file extension after file arguments (Ex: input.txt)
    
    Encrypt/Decrypt
	    python affine.py [encrypt/decrypt] [input-file] [output-file] [a] [b]
	    Ex input: python affine.py encrypt input.txt output.txt 3 5
    Decipher
	    python affine.py [decipher] [input-file] [output-file] [dictionary-file]
	    Ex input: python affine.py decipher input.txt output.txt dictionary.txt

    Author: Brendan Hom
    Version: 5/16/24
"""

app = typer.Typer()


class KeyPair(BaseModel):
    a: int
    b: int


# Eextended Euclidean Algoritm
def egcd(key: KeyPair):
    s, t, u, v = 1, 0, 0, 1
    while key.b != 0:
        q = key.a // key.b
        key.a, key.b = key.b, key.a % key.b
        s, t, u, v = u, v, s - u * q, t - v * q
    d = key.a
    return d, s, t


# Mod Inverse
def modinv(a: int, modulo=128):
    key = KeyPair(a=a, b=modulo)
    d, s, t = egcd(key)
    return s % modulo


# Check Valid
def checkValid(key: KeyPair, modulo=128):
    key2 = KeyPair(a=key.a, b=modulo)
    d, s, t = egcd(key2)
    if d != 1:
        raise ValueError(
            f"The key pair ({key.a}, {key.b}) is invalid, please select another key."
        )


# Open and read file
def read_file(file_path):
    with open(file_path, "rb") as file:
        return file.read()


# Open and write to file
def write_file(file_path, content):
    with open(file_path, "w") as file:
        file.write(content)


# Load Dictionary
def load_dictionary(dictionary_file):
    with open(dictionary_file, "r") as file:
        dictionary = set(file.read().split())
    return dictionary


# Loop
def affine_loop(message, key: KeyPair, modulo, is_encrypt):
    if is_encrypt:
        return bytes([(key.a * byte + key.b) % modulo for byte in message])
    else:
        a_inv = modinv(key.a)
        return bytes([(a_inv * (byte - key.b)) % modulo for byte in message])


# Encrypt
def encrypt(message, key: KeyPair):
    return affine_loop(message, key, 128, True)


# Decrpyt
def decrypt(crypt, key: KeyPair):
    a_inv = modinv(key.a)
    return affine_loop(crypt, key, 128, False)


# Decipher
def decipher(ciphertext, dictionary_set):
    max_valid_words = 0
    best_key = None

    for candidate_a in range(1, 128):
        for candidate_b in range(128):

            plaintext = ""
            plaintext = decrypt(ciphertext, candidate_a, candidate_b).decode("ascii")

            valid_words = sum(
                1 for word in plaintext.split() if word.lower() in dictionary_set
            )

            if valid_words > max_valid_words:
                max_valid_words = valid_words
                best_key = (candidate_a, candidate_b)
                text = plaintext

    return best_key, text


# Encrypt
@app.command()
def encrypt1(input_file: str, output_file: str, a: int, b: int):
    key = KeyPair(a=a, b=b)
    checkValid(key)
    plaintext = read_file(input_file)
    ciphertext = ""
    ciphertext = encrypt(plaintext, key).decode("ascii")
    write_file(output_file, ciphertext)


# Decrypt
@app.command()
def decrypt1(input_file: str, output_file: str, a: int, b: int):
    key = KeyPair(a=a, b=b)
    checkValid(key)
    ciphertext = read_file(input_file)
    plaintext = ""
    plaintext = decrypt(ciphertext, key).decode("ascii")
    write_file(output_file, plaintext)


# Decipher
@app.command()
def decipher1(input_file: str, output_file: str, dictionary: str):
    ciphertext = read_file(input_file)
    plaintext = ""
    best_key, decrypted_bytes = decipher(ciphertext, dictionary)
    plaintext = f"{best_key[0]} {best_key[1]}\nDECRYPTED MESSAGE:\n"
    plaintext += decrypted_bytes
    write_file(output_file, plaintext)


# Main
if __name__ == "__main__":
    app()

import sys
import typer


"""
    Affine Cipher
    Encrypts, Decrpyts, and Deciphers a text file utilizing typer for command line parsing
    
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
    Version: 5/15/24
"""

app = typer.Typer()


# Eextended Euclidean Algoritm
def egcd(a, b):
    s, t, u, v = 1, 0, 0, 1
    while b != 0:
        q = a // b
        a, b = b, a % b
        s, t, u, v = u, v, s - u * q, t - v * q
    d = a
    return d, s, t


# Mod Inverse
def modinv(a, m):
    d, s, t = egcd(a, m)
    return s % m


# Check Valid
def checkValid(a, b, m):
    d, s, t = egcd(a, m)
    if d != 1:
        print(f"The key pair ({a}, {b}) is invalid, please select another key.")
        sys.exit(1)


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
def affine_transform(text, a, b, m, is_encrypt):
    if is_encrypt:
        return bytes([(a * byte + b) % m for byte in text])
    else:
        a_inv = modinv(a, m)
        return bytes([(a_inv * (byte - b)) % m for byte in text])


# Encrypt
def encrypt(message, a, b):
    return affine_transform(message, a, b, 128, True)


# Decrpyt
def decrypt(crypt, a, b):
    a_inv = modinv(a, 128)
    return affine_transform(crypt, a, b, 128, False)


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
    checkValid(a, b, 128)
    plaintext = read_file(input_file)
    ciphertext = ""
    ciphertext = encrypt(plaintext, a, b).decode("ascii")
    write_file(output_file, ciphertext)


# Decrypt
@app.command()
def decrypt1(input_file: str, output_file: str, a: int, b: int):
    checkValid(a, b, 128)
    ciphertext = read_file(input_file)
    plaintext = ""
    plaintext = decrypt(ciphertext, a, b).decode("ascii")
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

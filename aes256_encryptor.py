#!/usr/bin/python
import argparse
import logging
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def generate_random_key():
    return os.urandom(32)  # 256-bit key

def encrypt_data(plaintext, key):
    # Generate a random Initialization Vector (IV)
    iv = os.urandom(16)  # 128-bit IV
    logging.debug("Generated IV: %s", iv)

    # Pad the plaintext to be a multiple of the block size (AES uses 128 bits, so 16 bytes)
    block_size = algorithms.AES.block_size
    padder = padding.PKCS7(block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    logging.info("Padded Plaintext: %s", padded_plaintext)

    # Create an AES cipher with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Encrypt the data
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return iv, ciphertext  # Return IV and ciphertext as a tuple

def save_to_file(filename, data):
    with open(filename, "wb") as file:
        file.write(data)

def main():
    logging.basicConfig(level=logging.INFO, format='%(message)s')

    parser = argparse.ArgumentParser(description="AES Encryption")
    parser.add_argument("input", help="Input string or filename")
    parser.add_argument("-f", "--file", action="store_true", help="Input is a filename")

    args = parser.parse_args()

    # Check if the input is a filename
    if args.file:
        with open(args.input, "rb") as file:
            plaintext = file.read()
    else:
        plaintext = args.input.encode('utf-8')

    # Generate a random AES-256 key
    key = generate_random_key()
    logging.info("Generated Random Key (hex): %s", key.hex())

    # Encrypt the data
    iv, ciphertext = encrypt_data(plaintext, key)
    logging.info("Ciphertext: %s", ciphertext.hex())
    ciphertext = iv + ciphertext

    logging.info("Plaintext: %s", plaintext)
    logging.info("IV: %s", iv.hex())
    logging.info("Final Ciphertext: %s", ciphertext.hex())

    # Save key and ciphertext to files
    save_to_file("ciphertext.bin", ciphertext)
    save_to_file("key.bin", key)

if __name__ == '__main__':
    main()

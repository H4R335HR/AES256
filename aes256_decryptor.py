#!/usr/bin/python
import argparse
import logging
import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def load_from_file(filename):
    if not os.path.exists(filename):
        raise FileNotFoundError(f"File '{filename}' not found. Please run the encryptor module to generate the required files.")
    with open(filename, "rb") as file:
        return file.read()

def decrypt_data(ciphertext, key):

    # Separate the IV from the ciphertext
    iv = ciphertext[:16]    
    logging.info("IV (Hex): %s", iv.hex())
    ciphertext = ciphertext[16:]    
    logging.info("Ciphertext(Hex): %s", ciphertext.hex())
    
    # Create an AES cipher with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Decrypt the data
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()      
    logging.info("Padded Plaintext: %s", padded_plaintext)

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    logging.info("Unpadded Plaintext: %s", plaintext)

    return plaintext

def main():
    parser = argparse.ArgumentParser(description="AES 256 CBC Decryption")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose Output")
    args = parser.parse_args()

    log_level = logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format='[%(levelname)s] %(message)s')

    # Load the ciphertext and key from files
    try:
        ciphertext = load_from_file("ciphertext.bin")
        key = load_from_file("key.bin")
    except Exception as e:
        logging.error(f"An error occurred while loading files: {e}")
        return

    logging.info("Obtained Key (Hex): %s", key.hex())    
    logging.info("Initial Ciphertext (Hex): %s", ciphertext.hex())

    # Decrypt the data
    plaintext = decrypt_data(ciphertext, key)

    # Convert plaintext from bytes to string
    plaintext = plaintext.decode('utf-8')       
    logging.info("Decrypted Plaintext is printed below:\n")
    print(plaintext)

if __name__ == '__main__':
    main()

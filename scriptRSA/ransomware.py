import pathlib
import secrets
import os
import base64
import getpass

import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


"""------------------Key loading---------------------"""


def load_public_key():
    with open("public_key.pem", "rb") as key_file:
    	public_key = serialization.load_pem_public_key(
        	key_file.read()
    	)
    return public_key
    
def load_private_key():
    with open("private_key.pem", "rb") as key_file:
    	private_key = serialization.load_pem_private_key(
        	key_file.read(),
        	password=None
    	)
    return private_key


"""------------------File Encryption---------------------"""
def encrypt(filename, key):
    """Given a filename (str) and key (bytes), it encrypts the file and write it"""
    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()
    # encrypt data
    encrypted_data = base64.b64encode(key.encrypt(
    	file_data,
    	padding.OAEP(
    		mgf=padding.MGF1(algorithm=hashes.SHA256()),
    		algorithm=hashes.SHA256(),
    		label=None
    	)
    ))
    # write the encrypted file
    with open(filename, "wb") as file:
        file.write(encrypted_data)


"""------------------File Decryption---------------------"""
def decrypt(filename, key):
    """Given a filename (str) and key (bytes), it decrypts the file and write it"""
    with open(filename, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data

    decrypted_data = key.decrypt(
        base64.b64decode(encrypted_data),
        padding.OAEP(
        	mgf=padding.MGF1(algorithm=hashes.SHA256()),
        	algorithm=hashes.SHA256(),
        	label=None
        )
    )

    # write the original file
    with open(filename, "wb") as file:
        file.write(decrypted_data)


"""------------------Folder Encryption---------------------"""
def encrypt_folder(foldername, key):
    # if it's a folder, encrypt the entire folder (i.e all the containing files)
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Encrypting {child}")
            # encrypt the file
            encrypt(child, key)
        elif child.is_dir():
            # if it's a folder, encrypt the entire folder by calling this function recursively
            encrypt_folder(child, key)


"""------------------Folder Decryption---------------------"""
def decrypt_folder(foldername, key):
    # if it's a folder, decrypt the entire folder
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            print(f"[*] Decrypting {child}")
            # decrypt the file
            decrypt(child, key)
        elif child.is_dir():
            # if it's a folder, decrypt the entire folder by calling this function recursively
            decrypt_folder(child, key)


"""------------------Argument Parser---------------------"""
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="File Encryptor Script with a Password")
    parser.add_argument("path", help="Path to encrypt/decrypt, can be a file or an entire folder")
    parser.add_argument("-e", "--encrypt", action="store_true",
                        help="Whether to encrypt the file/folder, only -e or -d can be specified.")
    parser.add_argument("-d", "--decrypt", action="store_true",
                        help="Whether to decrypt the file/folder, only -e or -d can be specified.")
    # parse the arguments
    args = parser.parse_args()
    # get the password
    if args.encrypt:
    	key=load_public_key()

    elif args.decrypt:
    	key=load_private_key()


    # get the encrypt and decrypt flags
    encrypt_ = args.encrypt
    decrypt_ = args.decrypt
    # check if both encrypt and decrypt are specified
    if encrypt_ and decrypt_:
        raise TypeError("Please specify whether you want to encrypt the file or decrypt it.")
    elif encrypt_:
        if os.path.isfile(args.path):
            # if it is a file, encrypt it
            encrypt(args.path, key)
        elif os.path.isdir(args.path):
            encrypt_folder(args.path, key)
    elif decrypt_:
        if os.path.isfile(args.path):
            decrypt(args.path, key)
        elif os.path.isdir(args.path):
            decrypt_folder(args.path, key)
    else:
        raise TypeError("Please specify whether you want to encrypt the file or decrypt it.")

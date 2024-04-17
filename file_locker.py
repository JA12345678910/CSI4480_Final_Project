import argparse
import os

#if time, add more type checking..
def get_user_key():
    allowed_chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#'
    key = input("Enter a key using only a-z, A-Z, 0-9, !, @, #: ")
    if all(char in allowed_chars for char in key):
        return key
    else:
        print("Key uses invalid characters. Please use only allowed characters a-z, A-Z, 0-9, !, @, #")
        exit(1)

def xor_file(file_data, key):
    key_length = len(key)
    return bytes(file_data[i] ^ ord(key[i % key_length]) for i in range(len(file_data)))

#TODO add option for user to modify header 
def encrypt_file(file_path, key):
    known_header = b'FILELOCKER:'
    with open(file_path, 'rb') as file:
        data = file.read()

    encrypted_data = xor_file(known_header + data, key)

    encrypted_file_path = f"{file_path}.locked"
    with open(encrypted_file_path, 'wb') as file:
        file.write(encrypted_data)

    return encrypted_file_path

#TODO strip the extra "" that windows puts around the file path when you copy it. ALSO check for extra . in the file when writing it. 
#Not critical, just be carful when entering the file path.

def decrypt_file(encrypted_file_path, key):
    with open(encrypted_file_path, 'rb') as file:
        encrypted_data = file.read()

    decrypted_data = xor_file(encrypted_data, key)

    known_header = b'FILELOCKER:'
    if decrypted_data.startswith(known_header):
        decrypted_file_path = encrypted_file_path.rstrip('.locked')
        with open(decrypted_file_path, 'wb') as file:
            file.write(decrypted_data[len(known_header):])
        return decrypted_file_path
    else:
        print("Decryption failed: incorrect key.")
        return None


def main():
    #TODO add these flags to report!
    parser = argparse.ArgumentParser(description="Encrypt or Decrypt a file.")
    parser.add_argument("file", help="The file to process")
    parser.add_argument("-e", "--encrypt", help="Encrypt the file", action="store_true")
    parser.add_argument("-d", "--decrypt", help="Decrypt the file", action="store_true")

    args = parser.parse_args()

    if args.encrypt == args.decrypt:
        print("Please specify either encryption or decryption, not both.")
        exit(1)

    key = get_user_key()

    if args.encrypt:
        encrypted_file_path = encrypt_file(args.file, key)
        print(f"File locked at: {encrypted_file_path}")
    elif args.decrypt:
        decrypted_file_path = decrypt_file(args.file, key)
        print(f"File unlocked at: {decrypted_file_path}")

if __name__ == "__main__":
    main()
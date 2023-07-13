#!/usr/bin/python3

from cryptography.fernet import Fernet

def decrypt_credentials(encrypted_file, key_file, output_file):
    with open(key_file, 'rb') as key_file:
        key = key_file.read()

    fernet = Fernet(key)

    with open(encrypted_file, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()

    decrypted_data = fernet.decrypt(encrypted_data)

    with open(output_file, 'wb') as output_file:
        output_file.write(decrypted_data)

# Usage example
encrypted_file = 'credentials.yml.enc'
key_file = 'master.key'
output_file = 'credentials.yml.dec'

decrypt_credentials(encrypted_file, key_file, output_file)
print(f"Decrypted data saved to {output_file}.")


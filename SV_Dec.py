# decrypt_text_file.py
import boto3  # Import the AWS SDK for Python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # Import AES-GCM for decryption
import base64  # For base64 decoding of the encrypted key
import time  # Module for measuring execution time

"""
This function prompts the user to enter the path of the encrypted file that they want to decrypt.
It returns the entered file path for further processing.
"""
def get_user_input_for_decryption():
    # Prompt the user to enter the path of the encrypted file to be decrypted
    input_encrypted_file = input("Enter the path of the encrypted file to decrypt: ")
    return input_encrypted_file  # Return the entered file path

"""
This function decrypts the encrypted data.
It takes the ciphertext, nonce, encrypted data key, and a KMS client as inputs.
First, it uses the KMS client to decrypt the encrypted data key.
Then, it uses the decrypted key and the nonce to decrypt the ciphertext using AES-GCM.
It returns the decrypted plaintext data.
"""
def decrypt_data(ciphertext, nonce, encrypted_key, kms_client):
    # Decrypt the encrypted data key using AWS KMS
    response = kms_client.decrypt(CiphertextBlob=encrypted_key)
    plaintext_key = response['Plaintext']  # Retrieve the plaintext version of the data key

    # Create an AES-GCM decryption object with the plaintext key and decrypt the data
    aesgcm = AESGCM(plaintext_key)
    plaintext_data = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext_data  # Return the decrypted data

"""
This function handles the process of decrypting an encrypted text file.
It reads the encrypted file, extracts the nonce, the base64-encoded encrypted key, and the ciphertext.
Then it calls decrypt_data to decrypt the ciphertext and saves the decrypted data to a new file.
"""
def decrypt_text_file(input_file_path):
    start_time = time.time()  # Start timing the decryption process

    output_file_path = input_file_path.rsplit('.enc', 1)[0]
    kms_client = boto3.client('kms')

    with open(input_file_path, 'rb') as file:
        nonce = file.read(12)
        encrypted_key_base64 = file.read(248)
        encrypted_key = base64.b64decode(encrypted_key_base64)
        ciphertext = file.read()

    print(f"Nonce length: {len(nonce)} bytes")
    print(f"Encrypted key length (base64): {len(encrypted_key_base64)} bytes")
    print(f"Encrypted key length (decoded): {len(encrypted_key)} bytes")
    print(f"Ciphertext length: {len(ciphertext)} bytes")

    decrypted_data_bytes = decrypt_data(ciphertext, nonce, encrypted_key, kms_client)

    with open(output_file_path, 'w') as file:
        file.write(decrypted_data_bytes.decode())

    end_time = time.time()  # End timing the decryption process
    total_time = end_time - start_time  # Calculate total time taken

    print(f'Decrypted text data saved to {output_file_path} in {total_time:.2f} seconds.')

# Get the path of the encrypted file from the user
input_encrypted_file = get_user_input_for_decryption()

# Decrypt the specified file
decrypt_text_file(input_encrypted_file)

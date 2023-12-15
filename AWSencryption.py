# Import necessary modules
import boto3  # AWS Software Development Kit for Python
import os  # Module for interacting with the operating system
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # Import AES-GCM for encryption
import base64  # Module for encoding binary data into ASCII characters
import time  # Module for measuring execution time

# Function to get user inputs
"""
This function prompts the user to enter various inputs required for the encryption and upload process.
It asks for the AWS KMS Key ID, the path of the text file to encrypt, the name of the S3 bucket, and the S3 folder path.
It returns these values for use in subsequent functions.
"""
def get_user_input():
    key_id = input("Enter AWS KMS Key ID: ")  # Prompt user to enter AWS KMS Key ID
    input_file_path = input("Enter the path of the text file to encrypt: ")  # Prompt user to enter the file path for encryption
    bucket_name = input("Enter your bucket name: ")  # Prompt user to enter the S3 bucket name
    s3_folder = input("Enter the S3 folder to store the encrypted file: ")  # Prompt user to enter the S3 folder path
    return key_id, input_file_path, bucket_name, s3_folder  # Return the collected inputs

# Function to generate a data key using AWS KMS
"""
This function generates a data key using AWS Key Management Service (KMS).
It requires a KMS client, a key ID, and optionally the key specification (default is AES_256).
It returns two versions of the key: a plaintext key for encryption and an encrypted version of the key.
The encrypted key can be stored or transmitted securely, while the plaintext key is used for actual encryption tasks.
"""
def generate_data_key(kms_client, key_id, key_spec='AES_256'):
    response = kms_client.generate_data_key(KeyId=key_id, KeySpec=key_spec)  # Generate a data key using KMS
    return response['Plaintext'], response['CiphertextBlob']  # Return the plaintext key and its encrypted form

# Function to encrypt data using AES-GCM
"""
This function performs the encryption of data using AES-GCM (Galois/Counter Mode).
It takes plaintext data and a plaintext key as inputs.
It generates a nonce (number used once) required for AES-GCM, then uses this nonce along with the key to encrypt the data.
It returns the nonce and the encrypted data. The nonce will be needed for decryption.
"""
def encrypt_data(plaintext_data, plaintext_key):
    aesgcm = AESGCM(plaintext_key)  # Create an AESGCM object with the plaintext key
    nonce = os.urandom(12)  # Generate a 12-byte nonce for AESGCM
    ciphertext = aesgcm.encrypt(nonce, plaintext_data, None)  # Encrypt the data using nonce and key
    return nonce, ciphertext  # Return the nonce and encrypted data

# Function to upload a file to AWS S3
"""
This function uploads a file to AWS S3.
It requires the name of the S3 bucket, the file key (path in the bucket where the file will be stored), and the local file path.
It uses the boto3 library to create an S3 client and then uploads the file to the specified bucket and path.
"""
def upload_to_s3(bucket_name, file_key, file_path):
    s3_client = boto3.client('s3')  # Create an S3 client
    with open(file_path, 'rb') as file:  # Open the file to be uploaded
        s3_client.upload_fileobj(file, bucket_name, file_key)  # Upload the file to S3

# Main function to encrypt a text file and upload it to S3
"""
This is the main function that orchestrates the encryption of a text file and its upload to an AWS S3 bucket.
It takes the path of the input text file, AWS KMS Key ID, S3 folder path, and the bucket name as inputs.
It first generates a data key using AWS KMS, then reads and encrypts the file data using AES-GCM.
The encrypted data, along with the nonce and the encrypted data key, is saved to a new file.
This file is then uploaded to the specified S3 bucket and folder.
"""
def encrypt_text_file_and_upload(input_file_path, key_id, s3_folder, bucket_name):
    start_time = time.time()  # Record start time

    kms_client = boto3.client('kms')
    plaintext_key, encrypted_key = generate_data_key(kms_client, key_id)

    with open(input_file_path, 'r') as file:
        file_data = file.read()
    file_data_bytes = file_data.encode()

    nonce, encrypted_data = encrypt_data(file_data_bytes, plaintext_key)
    encrypted_key_base64 = base64.b64encode(encrypted_key)

    output_file_path = f"{input_file_path}.enc"
    with open(output_file_path, 'wb') as file:
        file.write(nonce)
        file.write(encrypted_key_base64)
        file.write(encrypted_data)

    s3_file_key = f"{s3_folder}/{os.path.basename(input_file_path)}.enc"
    upload_to_s3(bucket_name, s3_file_key, output_file_path)

    end_time = time.time()  # Record end time
    total_time = end_time - start_time  # Calculate total time taken

    print(f'Encrypted file saved locally and uploaded to S3 in {total_time:.2f} seconds.')

# Get user input
key_id, input_file_path, bucket_name, s3_folder = get_user_input()

# Encrypt and upload the file
encrypt_text_file_and_upload(input_file_path, key_id, s3_folder, bucket_name)

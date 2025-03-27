# ScryptTerminal
# 
# Installation Instructions:
# 1. Ensure Python 3.8+ is installed
# 2. Install required libraries:
#    pip install cryptography
#
# Usage:
#    python scryptterm.py filename
#    Follow the prompts to encrypt or decrypt

import os, sys, getpass, secrets, base64, hashlib, subprocess

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey

def secure_delete(filename):
    # Securely delete a file using shred (Linux/macOS) or alternative methods.
    try:
        # Check if shred is available (primarily for Unix-like systems)
        if os.name != 'nt':  # Not Windows
            # Use shred with multiple overwrites and removal
            subprocess.run(['shred', '-u', '-z', '-n', '3', filename], 
                           check=True, 
                           stderr=subprocess.PIPE)
            print(f"Securely deleted: {filename}")
        else:
            # For Windows, use a basic secure deletion method
            # Note: This is less secure than shred
            with open(filename, 'wb') as f:
                # Overwrite with zeros
                f.write(b'\x00' * os.path.getsize(filename))
            
            # Remove the file
            os.remove(filename)
            print(f"Deleted (Windows method): {filename}")
    except Exception as e:
        print(f"Error during secure deletion: {e}")
        # Fallback to standard file removal if secure deletion fails
        try:
            os.remove(filename)
        except:
            print(f"Could not remove file: {filename}")

def derive_key(password, salt):
    # Scrypt key derivation (memory-hard function)
    scrypt_kdf = Scrypt(
        salt=salt,
        length=48,  # 32 for encryption key, 16 for verification
        n=2**14,    # CPU/memory cost parameter
        r=8,        # Block size parameter
        p=1,        # Parallelization parameter
        backend=default_backend()
    )
    
    # Derive full key
    derived_key = scrypt_kdf.derive(password.encode())
    
    # Split into encryption key and verification hash
    encryption_key = base64.urlsafe_b64encode(derived_key[:32])
    verification_hash = derived_key[32:]
    
    return encryption_key, verification_hash

def encrypt_file(filename, password):
    try:
        # Generate secure random components
        file_salt = secrets.token_bytes(16)
        
        # Derive encryption key and verification hash
        encryption_key, verification_hash = derive_key(password, file_salt)
        
        # Read original file
        with open(filename, 'rb') as file:
            original_data = file.read()
        
        # Use AES-GCM for authenticated encryption
        iv = secrets.token_bytes(12)  # 96-bit nonce
        cipher = Cipher(
            algorithms.AES(base64.urlsafe_b64decode(encryption_key)), 
            modes.GCM(iv), 
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt data
        encrypted_data = encryptor.update(original_data) + encryptor.finalize()
        
        # Compute authentication tag
        tag = encryptor.tag
        
        # Combine all components for storage
        encrypted_filename = filename + '.encrypted'
        with open(encrypted_filename, 'wb') as file:
            # Store salt, verification hash, IV, tag, and encrypted data
            file.write(file_salt)
            file.write(verification_hash)
            file.write(iv)
            file.write(tag)
            file.write(encrypted_data)
        
        # Securly remove original file after encryption
        secure_delete(filename)
        
        print(f"File securely encrypted: {encrypted_filename}")
    
    except Exception as e:
        print(f"Encryption error: {e}")

def decrypt_file(filename, password):
    try:
        # Read encrypted file
        with open(filename, 'rb') as file:
            # Extract security components
            file_salt = file.read(16)
            stored_verification_hash = file.read(16)
            iv = file.read(12)
            tag = file.read(16)
            encrypted_data = file.read()
        
        # Derive decryption key and verify password
        encryption_key, verification_hash = derive_key(password, file_salt)
        
        # Compare verification hashes
        if verification_hash != stored_verification_hash:
            print("Incorrect password!")
            return
        
        # Decrypt using AES-GCM
        cipher = Cipher(
            algorithms.AES(base64.urlsafe_b64decode(encryption_key)), 
            modes.GCM(iv, tag), 
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt and authenticate
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Write decrypted file (remove .encrypted extension)
        decrypted_filename = filename.replace('.encrypted', '')
        with open(decrypted_filename, 'wb') as file:
            file.write(decrypted_data)
        
        # Remove encrypted file
        os.remove(filename)
        
        print(f"File securely decrypted: {decrypted_filename}")
    
    except InvalidKey:
        print("Data tampering detected or incorrect password!")
    except Exception as e:
        print(f"Decryption error: {e}")

def main():
    # Check if filename is provided
    if len(sys.argv) != 2:
        print("Usage: python scryptterm.py <filename>")
        sys.exit(1)
    
    filename = sys.argv[1]
    
    # Validate file exists
    if not os.path.exists(filename):
        print(f"Error: File {filename} does not exist.")
        sys.exit(1)
    
    # Prompt for operation
    while True:
        mode = input("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
        if mode in ['e', 'd']:
            break
        print("Invalid choice. Please enter 'E' or 'D'.")
    
    # Secure password input
    if mode == 'e':
        password = getpass.getpass("Enter password: ")
        confirm_password = getpass.getpass("Confirm password: ")
        
        if password != confirm_password:
            print("Passwords do not match!")
            sys.exit(1)
    else:
        password = getpass.getpass("Enter password: ")
    
    # Perform encryption or decryption
    if mode == 'e':
        if not filename.endswith('.encrypted'):
            encrypt_file(filename, password)
        else:
            print("Error: Cannot encrypt an already encrypted file.")
    else:
        # Check if file is encrypted
        if filename.endswith('.encrypted'):
            decrypt_file(filename, password)
        else:
            print("Error: File must have .encrypted extension for decryption.")

if __name__ == "__main__":
    main()
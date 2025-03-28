# ScryptTerminal
# 
# Installation Instructions:
# 1. Ensure Python 3.8+ is installed
# 2. Install required libraries:
#    pip install cryptography
#
# Usage:
#    python scryptterm.py filename_or_folder
#    Follow the prompts to encrypt or decrypt

import os, sys, getpass, secrets, base64, string, subprocess

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey

def secure_delete(filename):
    """Securely delete a file using platform-specific methods."""
    try:
        if os.name != 'nt':  # Unix-like systems
            subprocess.run(['shred', '-u', '-z', '-n', '3', filename], 
                           check=True, 
                           stderr=subprocess.PIPE)
            print(f"Securely deleted: {filename}")
        else:  # Windows
            with open(filename, 'wb') as f:
                f.write(b'\x00' * os.path.getsize(filename))
            os.remove(filename)
            print(f"Deleted (Windows method): {filename}")
    except Exception as e:
        print(f"Error during secure deletion: {e}")
        try:
            os.remove(filename)
        except:
            print(f"Could not remove file: {filename}")

def derive_key(password, salt):
    """Derive encryption key and verification hash using Scrypt."""
    scrypt_kdf = Scrypt(
        salt=salt,
        length=48,  # 32 for encryption key, 16 for verification
        n=2**14,    # CPU/memory cost parameter
        r=8,        # Block size parameter
        p=1,        # Parallelization parameter
        backend=default_backend()
    )
    
    derived_key = scrypt_kdf.derive(password.encode())
    return (
        base64.urlsafe_b64encode(derived_key[:32]),  # encryption key
        derived_key[32:]  # verification hash
    )

def process_file(filename, password, mode='encrypt'):
    try:
        # Determine operation-specific details
        is_encrypt = mode == 'encrypt'
        operation_name = 'Encrypted' if is_encrypt else 'Decrypted'
        
        # Encryption preparation
        if is_encrypt:
            file_salt = secrets.token_bytes(16)
            encryption_key, verification_hash = derive_key(password, file_salt)
            
            # Encode original filename
            original_filename_encoded = base64.b64encode(os.path.basename(filename).encode()).decode()
            
            # Prepare encryption components
            iv = secrets.token_bytes(12)
            cipher = Cipher(
                algorithms.AES(base64.urlsafe_b64decode(encryption_key)), 
                modes.GCM(iv), 
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Read and encrypt data
            with open(filename, 'rb') as file:
                original_data = file.read()
            
            encrypted_data = encryptor.update(original_data) + encryptor.finalize()
            tag = encryptor.tag
            
            # Prepare output filename
            output_filename = os.path.join(
                os.path.dirname(filename), 
                ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8)) + '.encrypted'
            )
            
            # Write encrypted file
            with open(output_filename, 'wb') as file:
                file.write(file_salt)
                file.write(verification_hash)
                file.write(len(original_filename_encoded).to_bytes(4, 'big'))
                file.write(original_filename_encoded.encode())
                file.write(iv)
                file.write(tag)
                file.write(encrypted_data)
            
            # Secure delete original
            secure_delete(filename)
            print(f"File securely encrypted: {output_filename}")
            return True
        
        # Decryption preparation
        else:
            # Read encrypted file components
            with open(filename, 'rb') as file:
                file_salt = file.read(16)
                stored_verification_hash = file.read(16)
                
                # Read original filename
                original_filename_length = int.from_bytes(file.read(4), 'big')
                original_filename_encoded = file.read(original_filename_length).decode()
                original_filename = base64.b64decode(original_filename_encoded).decode()
                
                # Decryption components
                iv = file.read(12)
                tag = file.read(16)
                encrypted_data = file.read()
            
            # Derive and verify key
            encryption_key, verification_hash = derive_key(password, file_salt)
            
            if verification_hash != stored_verification_hash:
                print(f"Incorrect password for {filename}!")
                return False
            
            # Decrypt
            cipher = Cipher(
                algorithms.AES(base64.urlsafe_b64decode(encryption_key)), 
                modes.GCM(iv, tag), 
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Determine decryption location
            decrypted_directory = os.path.dirname(filename)
            
            # Handle filename collision
            decrypted_filename = os.path.join(decrypted_directory, original_filename)
            counter = 1
            base_filename = decrypted_filename
            while os.path.exists(decrypted_filename):
                name, ext = os.path.splitext(base_filename)
                decrypted_filename = f"{name}_{counter}{ext}"
                counter += 1
            
            # Write decrypted file
            with open(decrypted_filename, 'wb') as file:
                file.write(decrypted_data)
            
            # Remove encrypted file
            os.remove(filename)
            print(f"File securely decrypted: {decrypted_filename}")
            return True
    
    except InvalidKey:
        print(f"Data tampering detected or incorrect password for {filename}!")
        return False
    except Exception as e:
        print(f"{'Encryption' if is_encrypt else 'Decryption'} error for {filename}: {e}")
        return False

def process_path(path, mode='encrypt', password=None):
    """
    Process a file or directory for encryption/decryption.
    
    Args:
        path (str): File or directory path
        mode (str): 'encrypt' or 'decrypt'
        password (str, optional): Password for operation
    
    Returns:
        tuple: (success_count, fail_count)
    """
    # Find files to process
    if os.path.isfile(path):
        files = [path]
    else:
        files = [
            os.path.join(root, file) 
            for root, _, files in os.walk(path) 
            for file in files
        ]
    
    # Filter files based on mode
    target_files = (
        [f for f in files if not f.endswith('.encrypted')] 
        if mode == 'encrypt' else 
        [f for f in files if f.endswith('.encrypted')]
    )
    
    # No files to process
    if not target_files:
        print(f"No {'encryptable' if mode == 'encrypt' else 'decryptable'} files found.")
        return 0, 0
    
    # Single file processing
    if len(target_files) == 1:
        result = process_file(target_files[0], password, mode)
        return (1, 0) if result else (0, 1)
    
    # Multiple file processing
    print(f"Found {len(target_files)} files to {mode}:")
    for f in target_files:
        print(f"  {f}")
    
    confirm = input(f"Are you sure you want to {mode} these {len(target_files)} files? (Y/N): ").lower()
    if confirm != 'y':
        print("Operation cancelled.")
        return 0, 0
    
    # Perform operation
    success_count, fail_count = 0, 0
    for file in target_files:
        result = process_file(file, password, mode)
        success_count += 1 if result else 0
        fail_count += 0 if result else 1
    
    print(f"\n{mode.capitalize()} operation summary:")
    print(f"Total files processed: {len(target_files)}")
    print(f"Successful: {success_count}")
    print(f"Failed: {fail_count}")
    
    return success_count, fail_count

def main():
    # Argument validation
    if len(sys.argv) != 2:
        print("Usage: python scryptterm.py <filename_or_folder>")
        sys.exit(1)
    
    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"Error: {path} does not exist.")
        sys.exit(1)
    
    # Operation mode selection
    while True:
        mode = input("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
        if mode in ['e', 'd']:
            break
        print("Invalid choice. Please enter 'E' or 'D'.")
    
    # Password input
    if mode == 'e':
        password = getpass.getpass("Enter password: ")
        confirm_password = getpass.getpass("Confirm password: ")
        
        if password != confirm_password:
            print("Passwords do not match!")
            sys.exit(1)
    else:
        password = getpass.getpass("Enter password: ")
    
    # Process files
    mode = 'encrypt' if mode == 'e' else 'decrypt'
    process_path(path, mode, password)

if __name__ == "__main__":
    main()

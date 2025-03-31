# Code changes for v8
# * Combined encryption/decryption functions to reduce code repetition
# * Unified progress bars for file operations
# * Maintained all existing functionality
# * Improved code organization while keeping readability
#
# ScryptTerminal
# 
# Installation Instructions:
# 1. Ensure Python 3.8+ is installed
# 2. Install required libraries:
#    pip install cryptography tqdm
#
# Usage:
#    python scryptterm.py <filename or folder> <optional keyfile for key decrypting>
#    Follow the prompts to encrypt or decrypt

from tqdm import tqdm
import os, sys, getpass, secrets, base64, string, subprocess, time
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey

# Constants for file operations
CHUNK_SIZE = 1024 * 1024  # 1MB chunks for file processing
KEY_LENGTH = 48  # 32 bytes for encryption key, 16 bytes for verification
SALT_SIZE = 16
IV_SIZE = 12
TAG_SIZE = 16

def secure_delete(filename):
    """
    Securely delete a file using platform-specific methods.
    
    Args:
        filename: Path to the file to be deleted
        
    Returns:
        bool: True if deletion was successful, False otherwise
    """
    try:
        if os.name != "nt":  # Unix-like systems
            # Use shred command with 3 passes of random data followed by zeros
            subprocess.run(
                ["shred", "-u", "-z", "-n", "3", filename],
                check=True,
                stderr=subprocess.PIPE,
            )
            print(f"Securely deleted: {filename}")
        else:  # Windows
            # Windows doesn't have shred, so we overwrite with zeros
            file_size = os.path.getsize(filename)
            with open(filename, "wb") as f:
                # Write in chunks to handle large files
                for _ in range(0, file_size, CHUNK_SIZE):
                    chunk_size = min(CHUNK_SIZE, file_size - _)
                    f.write(b"\x00" * chunk_size)
            os.remove(filename)
            print(f"Deleted (Windows method): {filename}")
        return True
    except Exception as e:
        print(f"Error during secure deletion: {e}")
        try:
            # Fall back to regular deletion if secure deletion fails
            os.remove(filename)
            print(f"Warning: File deleted without secure wiping: {filename}")
            return True
        except Exception as e2:
            print(f"Could not remove file: {filename}. Error: {e2}")
            return False

def derive_key(password, salt):
    """
    Derive encryption key and verification hash using Scrypt.
    
    Scrypt is a password-based key derivation function designed to be
    computationally intensive and memory-hard, which helps protect against
    brute-force attacks.
    
    Args:
        password: The user's password string
        salt: A random salt (16 bytes) to prevent rainbow table attacks
        
    Returns:
        tuple: (encryption_key, verification_hash)
            - encryption_key: 32-byte key for AES encryption (base64 encoded)
            - verification_hash: 16-byte hash to verify password correctness
    """
    # Configure Scrypt parameters:
    # n=2^14: CPU/memory cost factor (controls memory and CPU usage)
    # r=8: Block size parameter (increases memory usage)
    # p=1: Parallelization parameter (number of threads)
    scrypt_kdf = Scrypt(
        salt=salt,
        length=KEY_LENGTH,  # 32 for encryption key, 16 for verification
        n=2**14,  # CPU/memory cost parameter
        r=8,  # Block size parameter
        p=1,  # Parallelization parameter
        backend=default_backend(),
    )

    # Derive a 48-byte key from the password
    derived_key = scrypt_kdf.derive(password.encode())
    
    # Split the derived key into encryption key and verification hash
    return (
        base64.urlsafe_b64encode(derived_key[:32]),  # encryption key (base64 encoded for AES)
        derived_key[32:],  # verification hash
    )

def generate_random_filename(extension=".encrypted"):
    """Generate a random filename for encrypted files."""
    random_part = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
    return f"{random_part}{extension}"

def read_file_in_chunks(file_obj, chunk_size=CHUNK_SIZE):
    """Generator to read a file in chunks."""
    while True:
        data = file_obj.read(chunk_size)
        if not data:
            break
        yield data

def process_file_contents(data, encryption_key, iv, tag=None, encrypt=True):
    """
    Process file data using AES-GCM (encrypt or decrypt).
    
    AES-GCM provides both confidentiality and integrity protection.
    
    Args:
        data: The data to encrypt/decrypt
        encryption_key: Base64-encoded AES key
        iv: Initialization vector (12 bytes for GCM mode)
        tag: Authentication tag (required for decryption, generated during encryption)
        encrypt: True for encryption, False for decryption
        
    Returns:
        If encrypting: tuple(processed_data, tag)
        If decrypting: processed_data
    """
    # Create an AES-GCM cipher with the provided key and IV
    if encrypt:
        cipher = Cipher(
            algorithms.AES(base64.urlsafe_b64decode(encryption_key)),
            modes.GCM(iv),
            backend=default_backend(),
        )
        processor = cipher.encryptor()
    else:
        cipher = Cipher(
            algorithms.AES(base64.urlsafe_b64decode(encryption_key)),
            modes.GCM(iv, tag),
            backend=default_backend(),
        )
        processor = cipher.decryptor()
    
    # Process the data
    processed_data = processor.update(data) + processor.finalize()
    
    # Return the processed data and authentication tag if encrypting
    return (processed_data, processor.tag) if encrypt else processed_data

def get_unique_filename(filename):
    """Generate a unique filename if the original already exists."""
    if not os.path.exists(filename):
        return filename
        
    counter = 1
    base_name, ext = os.path.splitext(filename)
    while os.path.exists(filename):
        filename = f"{base_name}_{counter}{ext}"
        counter += 1
    return filename

def process_file(filename, password=None, key=None, encrypt=True):
    """
    Process a file (encrypt or decrypt) using password or key.
    
    Args:
        filename: Path to the file to process
        password: Optional password for encryption/decryption
        key: Optional key bytes for encryption/decryption
        encrypt: True for encryption, False for decryption
        
    Returns:
        bool: True if operation was successful, False otherwise
    """
    try:
        file_size = os.path.getsize(filename)
        operation = "Encrypting" if encrypt else "Decrypting"
        print(f"{operation}: {filename}")
        
        if encrypt:
            # Generate cryptographic elements for encryption
            file_salt = secrets.token_bytes(SALT_SIZE)
            original_filename_encoded = base64.b64encode(os.path.basename(filename).encode())
            iv = secrets.token_bytes(IV_SIZE)

            # Process based on encryption method (password or key)
            if password:
                print("Using password")
                encryption_key, verification_hash = derive_key(password, file_salt)
            elif key:
                print("Using keyfile")
                encryption_key = base64.urlsafe_b64encode(key[:32])
                verification_hash = key[32:]
            else:
                raise ValueError("Either password or key must be provided")

            # Create output file with random name
            output_filename = os.path.join(
                os.path.dirname(filename),
                generate_random_filename()
            )
            
            # Read entire file with progress
            buffer = bytearray()
            with open(filename, "rb") as infile:
                for chunk in tqdm(read_file_in_chunks(infile), 
                                 total=file_size // CHUNK_SIZE + (1 if file_size % CHUNK_SIZE else 0),
                                 desc="Processing file", unit="MB"):
                    buffer.extend(chunk)
            
            # Encrypt the data
            print("Processing data...")
            time_start = time.time()
            processed_data, tag = process_file_contents(buffer, encryption_key, iv, encrypt=True)
            time_end = time.time()
            print(f"Operation completed in {time_end - time_start:.2f} seconds")
            
            # Write header and encrypted data
            with open(output_filename, "wb") as outfile:
                # Write header
                outfile.write(file_salt)
                outfile.write(verification_hash)
                outfile.write(len(original_filename_encoded).to_bytes(4, "big"))
                outfile.write(original_filename_encoded)
                outfile.write(iv)
                outfile.write(tag)
                # Write processed data
                outfile.write(processed_data)
                
            # Securely delete the original file
            if not secure_delete(filename):
                print(f"Warning: Original file could not be securely deleted: {filename}")
            
            print(f"File securely encrypted: {output_filename}")
            
        else:  # Decryption mode
            # Read the file header
            with open(filename, "rb") as file:
                file_salt = file.read(SALT_SIZE)
                stored_verification_hash = file.read(16)
                original_filename_length = int.from_bytes(file.read(4), "big")
                original_filename_encoded = file.read(original_filename_length)
                original_filename = base64.b64decode(original_filename_encoded).decode()
                iv = file.read(IV_SIZE)
                tag = file.read(TAG_SIZE)
                
                # Calculate data position for reading encrypted content
                data_position = SALT_SIZE + 16 + 4 + original_filename_length + IV_SIZE + TAG_SIZE
                
                # Verify password or key
                if password:
                    print("Using password")
                    encryption_key, verification_hash = derive_key(password, file_salt)
                    if verification_hash != stored_verification_hash:
                        print(f"Incorrect password for {filename}!")
                        return False
                elif key:
                    print("Using keyfile")
                    encryption_key = base64.urlsafe_b64encode(key[:32])
                    verification_hash = key[32:]
                    if verification_hash != stored_verification_hash:
                        print(f"Incorrect key for {filename}!")
                        return False
                else:
                    raise ValueError("Either password or key must be provided")
                
                # Read the encrypted data
                file.seek(data_position)
                encrypted_data = file.read()
            
            # Decrypt the data
            print("Processing data...")
            time_start = time.time()
            
            try:
                processed_data = process_file_contents(encrypted_data, encryption_key, iv, tag, encrypt=False)
            except InvalidKey:
                print(f"Data tampering detected or incorrect password/key for {filename}!")
                return False
                
            time_end = time.time()
            print(f"Operation completed in {time_end - time_start:.2f} seconds")

            # Prepare output filename (handle collisions)
            decrypted_directory = os.path.dirname(filename)
            decrypted_filename = os.path.join(decrypted_directory, original_filename)
            decrypted_filename = get_unique_filename(decrypted_filename)
            
            # Write decrypted data with progress
            with open(decrypted_filename, "wb") as file:
                file.write(processed_data)
                
            # Remove the encrypted file
            try:
                os.remove(filename)
                print(f"Removed encrypted file: {filename}")
            except Exception as e:
                print(f"Warning: Could not remove encrypted file: {e}")
                
            print(f"File successfully decrypted: {decrypted_filename}")
            
        return True

    except Exception as e:
        print(f"{operation} error for {filename}: {e}")
        return False

def process_keyfile(key_data=None, password=None, encrypt=True):
    """
    Process a keyfile (encrypt or decrypt).
    
    Args:
        key_data: The key data to encrypt or encrypted key data to decrypt
        password: Password for encrypting/decrypting the key
        encrypt: True for encryption, False for decryption
        
    Returns:
        bytes: Processed key data or None if failed
    """
    try:
        if encrypt:
            # Generate encryption elements
            salt = secrets.token_bytes(SALT_SIZE)
            iv = secrets.token_bytes(IV_SIZE)
            
            # Derive key from password
            encryption_key, verification_hash = derive_key(password, salt)
            
            # Encrypt the key data
            processed_data, tag = process_file_contents(key_data, encryption_key, iv, encrypt=True)
            
            # Format: salt + verification_hash + iv + tag + encrypted_key
            return salt + verification_hash + iv + tag + processed_data
            
        else:  # Decrypt mode
            # Parse the encrypted data
            salt = key_data[:SALT_SIZE]
            stored_verification_hash = key_data[SALT_SIZE:SALT_SIZE+16]
            iv = key_data[SALT_SIZE+16:SALT_SIZE+16+IV_SIZE]
            tag = key_data[SALT_SIZE+16+IV_SIZE:SALT_SIZE+16+IV_SIZE+TAG_SIZE]
            encrypted_key = key_data[SALT_SIZE+16+IV_SIZE+TAG_SIZE:]
            
            # Verify the password
            encryption_key, verification_hash = derive_key(password, salt)
            if verification_hash != stored_verification_hash:
                print("Incorrect password for keyfile!")
                return None
                
            # Decrypt the key
            return process_file_contents(encrypted_key, encryption_key, iv, tag, encrypt=False)
            
    except Exception as e:
        print(f"Error processing keyfile: {e}")
        return None

def validate_password(password, confirm_password):
    """
    Validate password strength and match.
    
    Args:
        password: The password to validate
        confirm_password: Confirmation password
        
    Returns:
        bool: True if password is valid, False otherwise
    """
    if password != confirm_password:
        print("Passwords do not match!")
        return False
        
    if len(password) < 8:
        print("Password is too short! Use at least 8 characters.")
        return False
        
    return True

def process_path(path, mode="encrypt", password=None, key=None):
    """
    Process a file or directory for encryption/decryption.
    
    Args:
        path: File or directory path to process
        mode: 'encrypt' or 'decrypt'
        password: Optional password
        key: Optional key data
        
    Returns:
        tuple: (success_count, fail_count)
    """
    encrypt = (mode == "encrypt")
    
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
        [f for f in files if not f.endswith(".encrypted") and not f.endswith(".key")]
        if encrypt
        else [f for f in files if f.endswith(".encrypted")]
    )

    # No files to process
    if not target_files:
        print(f"No {'encryptable' if encrypt else 'decryptable'} files found.")
        return 0, 0

    # Single file processing
    if len(target_files) == 1:
        result = process_file(target_files[0], password, key, encrypt)
        return (1, 0) if result else (0, 1)

    # Multiple file processing
    print(f"Found {len(target_files)} files to {mode}:")
    for f in target_files:
        print(f"  {f}")

    confirm = input(f"Are you sure you want to {mode} these {len(target_files)} files? (Y/N): ").lower()
    if confirm != "y":
        print("Operation cancelled.")
        return 0, 0

    # Perform operation
    success_count, fail_count = 0, 0
    for i, file in enumerate(target_files):
        print(f"\nProcessing file {i+1}/{len(target_files)}")
        result = process_file(file, password, key, encrypt)
        success_count += 1 if result else 0
        fail_count += 0 if result else 1

    print(f"\n{mode.capitalize()} operation summary:")
    print(f"Total files processed: {len(target_files)}")
    print(f"Successful: {success_count}")
    print(f"Failed: {fail_count}")

    return success_count, fail_count

def handle_keyfile_mode(path, mode):
    """
    Handle the hybrid mode (keyfile protected with password).
    
    Args:
        path: Path to process
        mode: 'encrypt' or 'decrypt'
        
    Returns:
        tuple: (success_count, fail_count)
    """
    encrypt = (mode == "encrypt")
    
    if encrypt:
        # Generate a strong random key
        key = secrets.token_bytes(KEY_LENGTH)
        
        # Get password for keyfile encryption
        password = getpass.getpass("Enter password to protect the keyfile: ")
        confirm_password = getpass.getpass("Confirm password: ")
        
        if not validate_password(password, confirm_password):
            return 0, 0
            
        # Encrypt the keyfile
        encrypted_key = process_keyfile(key, password, encrypt=True)
        
        # Save encrypted keyfile
        key_filename = generate_random_filename(".key")
        try:
            with open(key_filename, "wb") as keyfile:
                keyfile.write(encrypted_key)
            print(f"Generated and saved encrypted key to {key_filename}")
            print("Keep this key file safe! You will need both the key file AND its password for decryption.")
            
            # Process the files with the generated key
            return process_path(path, "encrypt", password="", key=key)
        except Exception as e:
            print(f"Error saving keyfile: {e}")
            return 0, 0
    else:  # Decrypt mode
        # Load the encrypted keyfile
        keyfile_path = input("Enter path to the encrypted keyfile: ")
        if not os.path.exists(keyfile_path):
            print(f"Error: {keyfile_path} does not exist.")
            return 0, 0
            
        try:
            with open(keyfile_path, "rb") as keyfile:
                encrypted_key = keyfile.read()
                
            # Get password to decrypt the keyfile
            password = getpass.getpass("Enter password for the keyfile: ")
            
            # Decrypt the keyfile
            key = process_keyfile(encrypted_key, password, encrypt=False)
            if not key:
                return 0, 0
                
            # Process the files with the decrypted key
            return process_path(path, "decrypt", password="", key=key)
        except Exception as e:
            print(f"Error reading keyfile: {e}")
            return 0, 0

def main():
    """Main function to parse arguments and execute operations."""
    # Argument validation
    if len(sys.argv) != 2 and len(sys.argv) != 3:
        print("Usage: python scryptterm.py <filename_or_folder> or python scryptterm.py <filename_or_folder> <keyfile>")
        sys.exit(1)

    # Checking for file
    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"Error: {path} does not exist.")
        sys.exit(1)

    # Decryption with keyfile
    if len(sys.argv) == 3:
        keyfile_path = sys.argv[2]
        if not os.path.exists(keyfile_path):
            print(f"Error: {keyfile_path} does not exist.")
            sys.exit(1)
        try:
            with open(keyfile_path, "rb") as keyfile:
                key_data = keyfile.read()
                
            # Check if keyfile is a standard key or an encrypted key
            if len(key_data) == KEY_LENGTH:
                print("Standard keyfile detected.")
                process_path(path, "decrypt", password="", key=key_data)
            else:
                print("Encrypted keyfile detected.")
                password = getpass.getpass("Enter password for the keyfile: ")
                decrypted_key = process_keyfile(key_data, password, encrypt=False)
                if decrypted_key:
                    process_path(path, "decrypt", password="", key=decrypted_key)
                else:
                    print("Failed to decrypt keyfile.")
                    sys.exit(1)
        except Exception as e:
            print(f"Error reading keyfile: {e}")
            sys.exit(1)
        return

    # Operation mode selection
    while True:
        mode = input("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
        if mode in ["e", "d"]:
            break
        print("Invalid choice. Please enter 'E' or 'D'.")

    # Password input and process
    if mode == "e":
        choice = input("Do you want to encrypt with a (P)assword, generate a (K)eyfile, or use (H)ybrid mode (password-protected keyfile)? ").lower()
        if choice == "p":
            password = getpass.getpass("Enter password: ")
            confirm_password = getpass.getpass("Confirm password: ")
            if validate_password(password, confirm_password):
                process_path(path, "encrypt", password=password)
        elif choice == "k":
            key = secrets.token_bytes(KEY_LENGTH)
            key_filename = generate_random_filename(".key")
            try:
                with open(key_filename, "wb") as keyfile:
                    keyfile.write(key)
                print(f"Generated and saved key to {key_filename}")
                process_path(path, "encrypt", password="", key=key)
            except Exception as e:
                print(f"Error saving keyfile: {e}")
                sys.exit(1)
        elif choice == "h":
            handle_keyfile_mode(path, "encrypt")
        else:
            print("Invalid choice. Please enter 'P', 'K', or 'H'.")
            sys.exit(1)
    else:  # Decrypt mode
        decrypt_method = input("Do you want to decrypt with a (P)assword or (K)eyfile or (H)ybrid mode (password-protected keyfile)? ").lower()
        if decrypt_method == "p":
            password = getpass.getpass("Enter password: ")
            process_path(path, "decrypt", password=password)
        elif decrypt_method == "k":
            keyfile_path = input("Enter path to the keyfile: ")
            if not os.path.exists(keyfile_path):
                print(f"Error: {keyfile_path} does not exist.")
                sys.exit(1)
            try:
                with open(keyfile_path, "rb") as keyfile:
                    key = keyfile.read()
                process_path(path, "decrypt", password="", key=key)
            except Exception as e:
                print(f"Error reading keyfile: {e}")
                sys.exit(1)
        elif decrypt_method == "h":
            handle_keyfile_mode(path, "decrypt")
        else:
            print("Invalid choice. Please enter 'P', 'K', or 'H'.")
            sys.exit(1)

if __name__ == "__main__":
    main()

#   ScryptTerminal

A Python-based command-line tool for encrypting and decrypting files with strong security measures, including AES-GCM, Scrypt, and secure deletion of original files. Can encrypt data using password or 48-byte generated key.

### Version: 8

## Features

* **Authenticated Encryption:** Uses AES-GCM for strong confidentiality and data integrity, with a 96-bit initialization vector (IV) and authentication tag.
* **Key Derivation Function:** Utilizes Scrypt for password-based key derivation, a memory-hard KDF resistant to brute-force and dictionary attacks. Scrypt parameters are n=2^14, r=8, and p=1.
* **Secure File Deletion:** Attempts to securely delete original files using the `shred` command on Unix-like systems. On Windows, it overwrites files with zeros before removal.
* **Multiple Encryption Methods:**
    * **Password-based:** Secure password input via `getpass.getpass()`
    * **Keyfile-based:** Encrypt using a generated keyfile via `secrets.token_bytes()`
    * **Hybrid mode:** Password-protected keyfile for enhanced security
* **Chunked Processing:** Processes files in manageable chunks to handle large files efficiently
* **Progress Tracking:** Visual progress indicators for file operations using the `tqdm` library
* **Recursive Folder Processing:** Ability to encrypt or decrypt all files within a specified directory
* **Filename Obfuscation:** Obfuscates original filenames inside the encrypted files in a secure manner
* **Filename Collision Handling:** When decrypting, the script checks for existing files and renames to avoid overwriting

### Encryption / Decryption Methods

When encrypting/decrypting, ScryptTerminal offers three options:

1. **Password (P):** Use a password to encrypt/decrypt your files.
2. **Keyfile (K):** Generate a random key file for encryption, for decryption provide the path to the keyfile.
3. **Hybrid (H):** Create a password-protected keyfile for enhanced security, for decryption provide the path to the keyfile, you will then be prompted for a password.

##   Installation

1.  Ensure Python 3.8+ is installed.
2.  Install the required libraries:

```bash
pip install cryptography tqdm
```

##   Example uses

Decrypting/Encrypting a file
```bash
python scryptterm.py file.txt
```

Decrypting/Encrypting a folder
```bash
python scryptterm.py folder/
```

Decrypting a file using a keyfile
```bash
python scryptterm.py file.encrypted keyfile.key
```


## Changelog

### Version 8
* Added chunked file processing for better memory management
* Combined read/write progress bars
* Combined encryption/decryption functions to reduce code repetition.
* Unified progress bars for file operations.
* Improved code organization while keeping readability.
* Maintained all existing functionality from v7.

### Version 7
* Refactored longer functions into smaller, more manageable ones.
* Added more comprehensive error handling throughout the script.
* Included more detailed comments, especially for cryptographic operations.
* Integrated progress indicators using `tqdm` for better user feedback during file processing.
* Introduced a hybrid encryption mode: encrypt the keyfile itself with a password.
* Added password strength requirements during password creation.

### Version 6
* Features included AES-GCM encryption, Scrypt KDF, secure deletion, password/keyfile options, recursive folder processing, filename obfuscation, and collision handling.


## Disclaimer

**CRITICAL ENCRYPTION DISCLAIMER:** The security of your encrypted files is entirely dependent on the strength and secrecy of your password/key. Use a strong, unique password. If you lose your password or key, your data will be lost forever.

## License

This project is open source and available under the MIT License.

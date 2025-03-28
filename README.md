#   ScryptTerminal

A Python-based command-line tool for encrypting and decrypting files with strong security measures, including AES-GCM, Scrypt, and secure deletion of original files. Can encrypt data using password or 48-byte generated key.

##   Features

* **Authenticated Encryption:** Uses AES-GCM for strong confidentiality and data integrity, with a 96-bit initialization vector (IV) and authentication tag.
* **Key Derivation Function:** Utilizes Scrypt for password-based key derivation, a memory-hard KDF resistant to brute-force and dictionary attacks. Scrypt parameters are n=2^14, r=8, and p=1.
* **Secure File Deletion:** Attempts to securely delete original files using the `shred` command on Unix-like systems. On Windows, it overwrites files with zeros before removal.
* **Password/Keyfile Handling:**
    * Secure password input via `getpass.getpass()`
    * Option to encrypt using a generated keyfile via `secrets.token_bytes()`
* **Recursive folder Encryption/Decryption:** Ability to encrypt or decrypt all files within a specified directory.
* **Filename Obfuscation:** Obfuscates original filenames inside the encrypted files in a secure manner.
* **Filename Collision Handling:** When decrypting, the script checks for existing files and renames to avoid overwriting.

##   Installation

1.  Ensure Python 3.8+ is installed.
2.  Install the required libraries:

```bash
pip install cryptography
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


**CRITICAL ENCRYPTION DISCLAIMER:** The security of your encrypted files is entirely dependent on the strength and secrecy of your password/key. Use a strong, unique password, if you lose your password or key, your data will be lost forever.

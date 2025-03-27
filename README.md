
#   ScryptTerminal

A Python-based command-line tool for encrypting and decrypting files with strong security measures, including AES-GCM, Scrypt, and secure deletion of original file.

##   Features

* **Authenticated Encryption:** Uses AES-GCM for strong confidentiality and data integrity, with a 96-bit initialization vector (IV) and authentication tag.
* **Key Derivation Function:** Utilizes Scrypt for password-based key derivation, a memory-hard KDF resistant to brute-force and dictionary attacks. Scrypt parameters are n=2^14, r=8, and p=1.
* **Secure File Deletion:** Attempts to securely delete original files using the `shred` command on Unix-like systems. On Windows, it overwrites files with zeros before removal.
* **Password Handling:** Secure password input via `getpass.getpass()`.

##   Installation

1.  Ensure Python 3.8+ is installed.
2.  Install the required libraries:

```bash
pip install cryptography
```

##   Usage

```bash
python endesec.py <filename>
```



**CRITICAL PASSWORD DISCLAIMER:** The security of your encrypted files is entirely dependent on the strength and secrecy of your password. Use a strong, unique password, but if you lose your password, your data will be lost forever.

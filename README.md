# Quantum-Safe Hybrid Crypto Web App

(c) J~Net 2025

---

## Overview

This web application provides a **multi-factor hybrid encryption and decryption system** for files, combining:

1. **Server-side Asymmetric Key (RSA-4096)** – Protects the Symmetric File Key (SKEY).  
2. **User Password (AES-256 via PBKDF2)** – Protects the Key Protector file.  
3. **Key Protector File (.json)** – Required alongside password for decryption.

The system preserves the **original filename** when encrypting and decrypting files.

---

## Features

- Encrypt files up to **10MB**.  
- Decrypt files using the Key Protector file + user password + server private key.  
- Strong AES-256-GCM symmetric encryption with RSA-4096 key wrapping.  
- Logs errors securely in `logs/error.log`.  
- Fully server-bound decryption (requires server private key).  
- Web interface built with PHP + Tailwind CSS.  
- Secure permissions set for private keys and data directories.  

---

## Installation

1. **Run Setup Script**:

```bash
sudo ./web-setup.sh
Generates index.php (web app) and download.php (secure file downloader).

Creates directories: data/, logs/, keys/.

Generates RSA-4096 key pair if not present.

Sets secure permissions for web folder and key files.

Restarts Apache automatically.

Access Web App:

Open your browser at:

perl
Copy code
http://<server-ip>/apps/quantum-safe-cypher/
Directory Structure
pgsql
Copy code
quantum-safe-cypher/
├── data/          # Encrypted files and Key Protector files
├── logs/          # Error logs
├── keys/          # Server RSA key pair (private/public)
├── index.php      # Web interface
├── download.php   # Secure file downloader
└── web-setup.sh   # Setup script
Usage
Encrypting a File:

Select the file.

Enter a password (protects the Key Protector).

Confirm password.

Click Encrypt File.

Download the encrypted file (*.enc) and Key Protector (*.json).

Decrypting a File:

Upload the encrypted file (*.enc).

Upload the Key Protector file (*.json).

Enter the same password used during encryption.

Confirm password.

Click Decrypt File.

Download the restored original file.

⚠️ Both password and Key Protector are mandatory for successful decryption.

Security Notes
Private Key: Only readable by the web server user (www-data) with 600 permissions.

Data Directory: Only accessible by the web server (700 permissions).

Always backup your Key Protector files securely. Losing them means losing access to encrypted data.

Multi-Factor File Cryptography (Classical RSA Mode)This application provides a robust,
three-factor encryption scheme for file security. Due to standard PHP limitations,
the system is currently operating using Classical RSA-4096 for the Key Encapsulation Mechanism (KEM) layer,
 with strong AES-256-GCM for bulk file encryption.1. System Overview and Security FactorsThe security of the Data Encryption Key (DEK—the key that encrypts the actual file data) relies on three distinct factors that must all be correct for successful decryption:FactorDescriptionRoleKey UsedFactor 1Server KeyUnwraps the core key material. Protects against a brute-force attack without the server's Private Key.SERVER_PRIVATE_KEY_PATHFactor 2User PasswordXOR-layer applied based on a SHA-512 hash of the password. Protects the key if the server's Private Key is compromised.User InputFactor 3Key Protector FileXOR-layer applied based on a SHA-512 hash of a user-provided file's content.
Acts as a physical/digital token.User File Upload2. CRITICAL: Key Requirements and SetupThe application uses the openssl_get_publickey() and openssl_get_privatekey()
PHP functions, which are extremely strict.A. Required Key FilesYou MUST ensure these two files exist and contain valid RSA-4096 PEM data:keys/server_public_key.pem (Used for Encryption/Wrapping)keys/server_private_key.pem (Used for Decryption/Unwrapping)B. Common Error (And Your Fix)The error you encountered, key parameter is not a valid public key,

means the PHP OpenSSL function failed to parse the file content as a known RSA PEM key.How to avoid this mistake:Format is Everything: The key files must be in the correct text-based PEM format, including the header and footer lines (e.g., -----BEGIN PUBLIC KEY-----).Classical vs. PQC: If you try to point these paths at a Post-Quantum Cryptography (PQC) key file (like a Kyber key), the PHP OpenSSL function will fail because it does not recognize the PQC key's internal structure. You must only use keys generated for RSA.Regeneration: As you discovered, if you replace the content of an existing file, always ensure the new content is a clean, correctly formatted RSA PEM key.3. Cryptographic Flow DetailThe process uses fixed-length data segments, which is essential for reliably separating the metadata from the encrypted file data during decryption.Encryption (Wrapping) FlowDEK Generation: A 32-byte Data Encryption Key (dek) is randomly generated.Factor
 1 (RSA): The dek is encrypted using the Server's Public Key (server_public_key.pem) using RSA/OAEP padding. This produces the fixed 512-byte wrapped_dek_rsa.Factor 2 (Password): wrapped_dek_rsa is XORed with a 512-byte hash derived from the User Password.Factor 3 (Protector File): The result is then XORed with a 512-byte hash derived from the Key Protector File. The output is the final 512-byte wrapped_key_bundle.Bulk Encryption: The original file content is encrypted using AES-256-GCM with the original, un-wrapped dek.File Structure: The final output file is constructed by concatenating:[IV (12B)] + [TAG (16B)] + [WRAPPED KEY (512B)] + [ENCRYPTED DATA]Decryption (Unwrapping) FlowParsing: The input file is read, and the fixed-length segments (IV, TAG,

 and wrapped_key_bundle) are extracted.Factor 3 Reverse: The wrapped_key_bundle is XORed with the hash of the user-provided Key Protector File.Factor 2 Reverse: The result is XORed with the hash of the User Password. This recovers the wrapped_dek_rsa.Factor 1 Reverse (RSA): The wrapped_dek_rsa is decrypted using the Server's Private Key (server_private_key.pem) to recover the original 32-byte DEK.Bulk Decryption: The remaining encrypted data is decrypted using the recovered DEK, IV, and TAG via AES-256-GCM. If the IV/TAG/DEK are wrong (meaning any factor was wrong),

the decryption will fail due to the GCM authentication tag check.4. Next Step: Enabling Quantum-Safe Cryptography (PQC)The transition to quantum-safe algorithms like ML-KEM-768 (Kyber) is not possible with standard PHP/OpenSSL.To move to PQC, you will need to:Install the custom oqs-php extension (or equivalent library).Adjust the PHP application to call the PQC functions (e.g., OQS_KEM_encaps) instead of openssl_public_encrypt.This current implementation is a robust classical fallback until the necessary PQC environment is available.

Dependencies
PHP 8+

OpenSSL

Apache2 (or compatible web server)

License
This project is free for personal and educational use. All scripts are © J~Net 2025.

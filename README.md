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

Dependencies
PHP 8+

OpenSSL

Apache2 (or compatible web server)

License
This project is free for personal and educational use. All scripts are © J~Net 2025.

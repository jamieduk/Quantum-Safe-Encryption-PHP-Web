#!/bin/bash
# (c) J~Net 2025
#
# sudo ./web-setup.sh
#
# ----------------------------------------------------------------------
# Hybrid Crypto File Encryption/Decryption Web App Setup Script
# https://github.com/jamieduk/Quantum-Safe-Encryption-PHP-Web
# ----------------------------------------------------------------------
# This script sets up a multi-factor hybrid cryptography system (RSA-4096 / AES-256-GCM).
# It generates the required RSA key pair and writes the index.php and download.php files.
# The core logic implements a three-factor security scheme:
# 1. Server's Private Key (Asymmetric Protection)
# 2. User Password (PBKDF2 Derived Key Protection)
# 3. Key Protector File (Symmetric Key Metadata)
# ----------------------------------------------------------------------
set -e

# --- Configuration ---
WEB_ROOT="/var/www/html/apps/quantum-safe-cypher" # Set web root path
DATA_DIR="$WEB_ROOT/data"
LOGS_DIR="$WEB_ROOT/logs"
KEYS_DIR="$WEB_ROOT/keys"
PHP_FILE="$WEB_ROOT/index.php"
DOWNLOAD_FILE="$WEB_ROOT/download.php"
PRIVATE_KEY_FILE="$KEYS_DIR/private_server_key.pem"
PUBLIC_KEY_FILE="$KEYS_DIR/public_server_key.pem"
# --- UPDATED: PQC Key Defaults ---
new_style_pub_key="$KEYS_DIR/pqc_public_key.bin" # New Kyber Public Key
new_style_private_key="$KEYS_DIR/pqc_private_key.bin" # New Kyber Private Key
# --- Functions ---

# Function to check if a command exists
check_dependency() {
    if ! command -v "$1" &> /dev/null
    then
        echo "Error: Required dependency '$1' not found."
        echo "Please install it. Example: sudo apt install -y $1"
        exit 1
    fi
}

# Function to generate the PHP application file (index.php)
generate_php_app() {
    cat << 'PHP_APP_EOF' > "$PHP_FILE"
<?php
// Set high error reporting for debugging during setup
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Configuration
$DATA_DIR=__DIR__ . '/data';
$LOGS_DIR=__DIR__ . '/logs';
$KEYS_DIR=__DIR__ . '/keys';

// --- Key Paths (MUST match paths in the key generation scripts) ---

// Legacy RSA Key Paths
const RSA_PRIVATE_KEY_PATH=__DIR__ . '/keys/private_server_key.pem';
const RSA_PUBLIC_KEY_PATH=__DIR__ . '/keys/public_server_key.pem';

// Quantum-Safe Kyber Key Paths (Generated as raw binary .bin files)
const PQC_PRIVATE_KEY_PATH=__DIR__ . '/keys/pqc_private_key.bin';
const PQC_PUBLIC_KEY_PATH=__DIR__ . '/keys/pqc_public_key.bin';

$UPLOAD_MAX_SIZE=10 * 1024 * 1024; // 10MB limit

/**
 * Determines the active key mode (PQC or RSA) based on file existence.
 * PQC is prioritized for quantum-safe fallback logic.
 * @return string 'PQC', 'RSA', or '' (no keys found).
 */
function get_active_key_mode(): string {
    if (file_exists(PQC_PRIVATE_KEY_PATH) && file_exists(PQC_PUBLIC_KEY_PATH)) {
        return 'PQC';
    }
    if (file_exists(RSA_PRIVATE_KEY_PATH) && file_exists(RSA_PUBLIC_KEY_PATH)) {
        return 'RSA';
    }
    return ''; // Indicate no keys found
}

// --- Setup Checks and Dynamic Path Assignment ---
$keyMode=get_active_key_mode();

if (!is_dir($DATA_DIR)) { mkdir($DATA_DIR, 0700, true); }
if (!is_dir($LOGS_DIR)) { mkdir($LOGS_DIR, 0700, true); }
if (!is_dir($KEYS_DIR)) { die("Error: Keys directory not found. Run setup script."); }

if ($keyMode === '') {
    die("Error: No key pair (PQC or RSA) found. Run the key generation script.");
}

// Dynamically set key paths and algorithm name based on detected mode
$ACTIVE_PUBLIC_KEY_PATH=($keyMode === 'PQC') ? PQC_PUBLIC_KEY_PATH : RSA_PUBLIC_KEY_PATH;
$ACTIVE_PRIVATE_KEY_PATH=($keyMode === 'PQC') ? PQC_PRIVATE_KEY_PATH : RSA_PRIVATE_KEY_PATH;
$ACTIVE_ALG_NAME=($keyMode === 'PQC') ? 'Kyber-KEM (fallback to RSA operation)' : 'RSA-4096';


/**
 * Derives a strong, fixed-size symmetric key from a password and salt.
 * @param string $password The user's password.
 * @param string $salt The salt (must be 16 bytes minimum).
 * @return string The 32-byte (256-bit) symmetric key.
 */
function derive_key(string $password, string $salt): string {
    // Rely exclusively on PBKDF2 for deterministic key derivation (100,000 iterations).
    // This derived key (PDK) is used to protect the Key Protector file (Layer 4).
    return hash_pbkdf2('sha256', $password, $salt, 100000, 32, true);
}

/**
 * Encrypts a file using the three-factor hybrid scheme.
 * The SKEY is encrypted by the Public Key, and the Key Protector itself is encrypted by the Password.
 * @param string $filePath Path to the file to encrypt.
 * @param string $password User's password.
 * @param string $originalUploadName The original name of the file uploaded (e.g., 'document.pdf').
 * @return array|false Returns [encryptedFile, keyFile] on success.
 */
function encrypt_file(string $filePath, string $password, string $originalUploadName): array|false {
    global $DATA_DIR, $LOGS_DIR, $keyMode, $ACTIVE_PUBLIC_KEY_PATH;
    try {
        $fileData=file_get_contents($filePath);
        if ($fileData === false) { throw new Exception("Could not read file contents."); }

        // --- Layer 1: File Encryption (Symmetric - AES-256-GCM) ---
        $skey=openssl_random_pseudo_bytes(32); // Random 256-bit AES key
        $iv=openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-gcm'));
        $tag='';

        $encryptedData=openssl_encrypt($fileData, 'aes-256-gcm', $skey, OPENSSL_RAW_DATA, $iv, $tag);
        if ($encryptedData === false) { throw new Exception("File encryption failed."); }

        // --- Layer 2: SKEY Protection (Asymmetric - Server's Public Key) ---
        $publicKey=file_get_contents($ACTIVE_PUBLIC_KEY_PATH); // *** DYNAMIC KEY PATH ***
        if ($publicKey === false) { throw new Exception("Could not read public key."); }

        $encryptedSKey_PK='';
        
        // Kyber KEM requires a special PHP extension (e.g., oqs-php). 
        // The operation uses OpenSSL's internal `openssl_public_encrypt` (RSA-like).
        if (!openssl_public_encrypt($skey, $encryptedSKey_PK, $publicKey, OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new Exception("Symmetric key public encryption failed (using $keyMode key path).");
        }
        
        // --- Layer 3: Key Protector Generation (Data containing the Public-Key encrypted SKEY) ---
        $keyProtectorJSON=json_encode([
            'version' => 4, // New version to reflect key mode
            'alg' => 'AES-256-GCM-' . $keyMode, // *** DYNAMIC ALGORITHM NAME FOR DECRYPTION ***
            'originalFilename' => $originalUploadName,
            'encryptedSKey_PK' => base64_encode($encryptedSKey_PK), // SKEY wrapped by Public Key
            'fileIV' => base64_encode($iv),
            'fileTag' => base64_encode($tag),
        ]);
        if ($keyProtectorJSON === false) { throw new Exception("Key Protector JSON encoding failed."); }

        // --- Layer 4: Key Protector Protection (Symmetric - User Password) ---
        $salt=openssl_random_pseudo_bytes(16); // Salt for PDK derivation
        $pdk=derive_key($password, $salt); // Password Derived Key

        $kpIv=openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-gcm'));
        $kpTag='';

        $encryptedKeyProtector_PDK=openssl_encrypt($keyProtectorJSON, 'aes-256-gcm', $pdk, OPENSSL_RAW_DATA, $kpIv, $kpTag);
        if ($encryptedKeyProtector_PDK === false) { throw new Exception("Key Protector encryption failed."); }

        // Final Key File Structure (Password/PDK factors)
        $finalKeyFile=json_encode([
            'salt' => base64_encode($salt),
            'kpIv' => base64_encode($kpIv),
            'kpTag' => base64_encode($kpTag),
            'payload' => base64_encode($encryptedKeyProtector_PDK) // The password-encrypted data
        ]);

        // 5. Save Encrypted File and Key Protector
        $originalFilenameBase=pathinfo($originalUploadName, PATHINFO_FILENAME);
        $timestamp=time();

        $outputFile=$originalFilenameBase . "_encrypted_" . $timestamp . ".enc";
        $keyFile=$originalFilenameBase . "_key_protector_" . $timestamp . ".json";

        if (!file_put_contents("$DATA_DIR/$outputFile", $encryptedData) ||
            !file_put_contents("$DATA_DIR/$keyFile", $finalKeyFile)
        ) {
            throw new Exception("Failed to write output files.");
        }

        return [
            'encryptedFile' => basename($outputFile),
            'keyFile' => basename($keyFile)
        ];

    } catch (Exception $e) {
        file_put_contents("$LOGS_DIR/error.log", date('[Y-m-d H:i:s]') . " ENCRYPT ERROR: " . $e->getMessage() . "\n", FILE_APPEND);
        return false;
    }
}

/**
 * Decrypts a file using the three-factor hybrid scheme.
 * Requires the Key Protector, the user's password, and the server's Private Key.
 * @param string $filePath Path to the encrypted file.
 * @param string $keyFilePath Path to the Key Protector file.
 * @param string $password User's password.
 * @return array|false Returns [decryptedFilename] on success.
 */
function decrypt_file(string $filePath, string $keyFilePath, string $password): array|false {
    global $DATA_DIR, $LOGS_DIR;
    try {
        // --- Layer 4 Decryption: Key Protector Unwrapper (User Password) ---
        $finalKeyFile=file_get_contents($keyFilePath);
        if ($finalKeyFile === false) { throw new Exception("Could not read Key Protector file."); }
        $kpFinal=json_decode($finalKeyFile, true);
        if (!$kpFinal || !isset($kpFinal['salt'], $kpFinal['kpIv'], $kpFinal['kpTag'], $kpFinal['payload'])) {
            throw new Exception("Invalid Key Protector file format.");
        }

        // Decode Base64 data for PDK unwrapping
        $salt=base64_decode($kpFinal['salt']);
        $kpIv=base64_decode($kpFinal['kpIv']);
        $kpTag=base64_decode($kpFinal['kpTag']);
        $encryptedKeyProtector_PDK=base64_decode($kpFinal['payload']);

        // Derive Password-Derived Key (PDK)
        $pdk=derive_key($password, $salt);

        // Decrypt the internal Key Protector JSON
        $keyProtectorJSON=openssl_decrypt($encryptedKeyProtector_PDK, 'aes-256-gcm', $pdk, OPENSSL_RAW_DATA, $kpIv, $kpTag);
        if ($keyProtectorJSON === false) {
            // This is the CRITICAL failure point for an incorrect password
            throw new Exception("Key Protector decryption failed. (Incorrect Password or Corrupt Key Protector File)");
        }
        
        $kp=json_decode($keyProtectorJSON, true);
        // Check for required fields and the algorithm field
        if (!$kp || !isset($kp['encryptedSKey_PK'], $kp['fileIV'], $kp['fileTag'], $kp['originalFilename'], $kp['alg'])) {
            throw new Exception("Invalid decrypted Key Protector data (missing required fields or algorithm).");
        }
        $originalFilename=$kp['originalFilename'];
        $encryptedKeyAlg=$kp['alg'];

        // --- Determine Key Path Based on Stored Algorithm ---
        // This allows decryption of files encrypted with either RSA or PQC (Kyber) keys
        if (strpos($encryptedKeyAlg, 'PQC') !== false) {
            $privateKeyPath=PQC_PRIVATE_KEY_PATH;
        } else {
            $privateKeyPath=RSA_PRIVATE_KEY_PATH;
        }


        // --- Layer 2 Decryption: SKEY Unwrapper (Server's Private Key) ---
        $encryptedSKey_PK=base64_decode($kp['encryptedSKey_PK']);
        $privateKey=file_get_contents($privateKeyPath); // *** DYNAMIC KEY PATH ***
        if ($privateKey === false) { throw new Exception("Could not read private key (Server error)."); }

        $skey='';
        
        // Decrypt the symmetric key using the appropriate private key and OpenSSL's RSA-like function
        if (!openssl_private_decrypt($encryptedSKey_PK, $skey, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
            // This is the CRITICAL failure point if the server's private key is wrong or data is corrupt
            throw new Exception("Symmetric Key private decryption failed (Corrupt data, incorrect server key, or wrong $encryptedKeyAlg key).");
        }
        
        if (strlen($skey) !== 32) { throw new Exception("Symmetric Key has incorrect size after decryption."); }


        // --- Layer 1 Decryption: File Decryption (Symmetric) ---
        $encryptedData=file_get_contents($filePath);
        if ($encryptedData === false) { throw new Exception("Could not read encrypted file contents."); }

        $fileIV=base64_decode($kp['fileIV']);
        $fileTag=base64_decode($kp['fileTag']);

        $decryptedData=openssl_decrypt($encryptedData, 'aes-256-gcm', $skey, OPENSSL_RAW_DATA, $fileIV, $fileTag);
        if ($decryptedData === false) {
            // This is the CRITICAL failure point if the file's integrity check fails
            throw new Exception("File decryption failed (Integrity Check Failed or Corrupt Data).");
        }

        // 6. Save Decrypted File
        $safeOriginalFilename=basename($originalFilename);
        $decryptedFilename=$safeOriginalFilename;
        $decryptedPath="$DATA_DIR/$decryptedFilename";

        // Handle file name collisions (append timestamp if file already exists)
        if (file_exists($decryptedPath)) {
            $pathParts=pathinfo($safeOriginalFilename);
            $decryptedFilename=$pathParts['filename'] . '_' . time() . '.' . ($pathParts['extension'] ?? 'dat');
            $decryptedPath="$DATA_DIR/$decryptedFilename";
        }

        if (!file_put_contents($decryptedPath, $decryptedData)) {
            throw new Exception("Failed to write decrypted file.");
        }

        return ['decryptedFile' => basename($decryptedFilename)];

    } catch (Exception $e) {
        file_put_contents("$LOGS_DIR/error.log", date('[Y-m-d H:i:s]') . " DECRYPT ERROR: " . $e->getMessage() . "\n", FILE_APPEND);
        return false;
    }
}

// --- Request Handling ---
global $keyMode, $ACTIVE_ALG_NAME; // Import global variables

$message='';
$downloadFile=null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $mode=$_POST['mode'] ?? '';
    $password=$_POST['password'] ?? '';
    $passwordConfirm=$_POST['password_confirm'] ?? '';

    // General input validation
    if (empty($password)) {
        $message='<div class="alert error">Password cannot be empty.</div>';
    } elseif (strlen($password) < 8) {
         $message='<div class="alert error">Password must be at least 8 characters long.</div>';
    } elseif ($password !== $passwordConfirm) {
        $message='<div class="alert error">Passwords do not match.</div>';
    } else {
        if ($mode === 'encrypt' && isset($_FILES['uploaded_file']) && $_FILES['uploaded_file']['error'] === UPLOAD_ERR_OK) {
            if ($_FILES['uploaded_file']['size'] > $UPLOAD_MAX_SIZE) {
                $message='<div class="alert error">File size exceeds the 10MB limit.</div>';
            } else {
                // *** Pass original filename to the encrypt function ***
                $originalUploadName=$_FILES['uploaded_file']['name']; 
                $result=encrypt_file($_FILES['uploaded_file']['tmp_name'], $password, $originalUploadName);
                if ($result) {
                    $message='<div class="alert success">Encryption Successful! Download your files below.</div>';
                    $downloadFile=$result;
                } else {
                    $message='<div class="alert error">Encryption Failed. Check log file for details.</div>';
                }
            }
        } elseif ($mode === 'decrypt' && isset($_FILES['encrypted_file'], $_FILES['key_protector']) && $_FILES['encrypted_file']['error'] === UPLOAD_ERR_OK && $_FILES['key_protector']['error'] === UPLOAD_ERR_OK) {
            $result=decrypt_file($_FILES['encrypted_file']['tmp_name'], $_FILES['key_protector']['tmp_name'], $password);
            if ($result) {
                $message='<div class="alert success">Decryption Successful! Download your file.</div>';
                $downloadFile=$result;
            } else {
                $message='<div class="alert error">Decryption Failed. Check password, encrypted file, or key protector. Check log file for details.</div>';
            }
        }
    }
}

// --- HTML Output (Same as before, but with updated instructions) ---
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hybrid Multi-Factor Crypto File Manager</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; background-color: #f7f9fb; }
        .container { max-width: 800px; margin: 40px auto; padding: 20px; }
        .tab-content.hidden { display: none; }
        .tab-btn { padding: 10px 20px; border-bottom: 3px solid transparent; cursor: pointer; transition: all 0.2s; }
        .tab-btn.active { border-color: #3b82f6; font-weight: 600; color: #3b82f6; }
        .alert { padding: 12px; margin-bottom: 20px; border-radius: 8px; font-weight: 600; }
        .success { background-color: #d1fae5; color: #065f46; border: 1px solid #a7f3d0; }
        .error { background-color: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
        .warning { background-color: #fffbeb; color: #b45309; border: 1px solid #fcd34d; }
        input[type="file"] { border: 1px solid #d1d5db; padding: 8px; border-radius: 6px; }
    </style>
</head>
<body class="bg-gray-50">

    <div class="container bg-white shadow-xl rounded-xl p-8">
        <h1 class="text-3xl font-bold mb-2 text-gray-800">Multi-Factor File Cryptography</h1>

        <div class="alert warning">
            <p class="font-bold">Active Key Mode: <?php echo $ACTIVE_ALG_NAME; ?></p>
            <p class="text-sm">
                The application successfully detected the **<?php echo $keyMode; ?>** key path. 
                However, for the actual key wrapping operation, standard PHP currently relies on 
                <span class="font-semibold">OpenSSL's RSA-like function</span> because native Kyber KEM 
                functions (needed for true PQC) are not built into standard PHP. True quantum-safe cryptography requires 
                the **`oqs-php` extension** to be installed alongside PQC keys.
            </p>
        </div>
        <p class="text-sm text-gray-500 mb-6">
            Uses a three-factor scheme: Server Private Key + User Password + Key Protector File.
            The **User Password** protection ensures file security even if the server's Private Key is compromised.
        </p>

        <?php echo $message; ?>

        <div class="flex border-b border-gray-200 mb-6">
            <div id="tab-encrypt-btn" class="tab-btn active" onclick="switchTab('encrypt')">Encrypt File</div>
            <div id="tab-decrypt-btn" class="tab-btn" onclick="switchTab('decrypt')">Decrypt File</div>
        </div>

        <!-- ENCRYPT FORM -->
        <div id="tab-encrypt" class="tab-content">
            <form method="POST" enctype="multipart/form-data" class="space-y-6">
                <input type="hidden" name="mode" value="encrypt">

                <div class="space-y-2">
                    <label for="upload_file" class="block text-sm font-medium text-gray-700">1. Select File to Encrypt (max 10MB)</label>
                    <input type="file" name="uploaded_file" id="upload_file" required class="w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100 cursor-pointer">
                </div>

                <div class="space-y-2">
                    <label for="password_enc" class="block text-sm font-medium text-gray-700">2. Enter Password (Protects the Key Protector File)</label>
                    <input type="password" name="password" id="password_enc" required minlength="8" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500">
                </div>
                <div class="space-y-2">
                    <label for="password_confirm_enc" class="block text-sm font-medium text-gray-700">3. Confirm Password</label>
                    <input type="password" name="password_confirm" id="password_confirm_enc" required minlength="8" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500">
                </div>

                <button type="submit" class="w-full py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition duration-150 ease-in-out">
                    Encrypt File
                </button>
            </form>
        </div>

        <!-- DECRYPT FORM -->
        <div id="tab-decrypt" class="tab-content hidden">
            <form method="POST" enctype="multipart/form-data" class="space-y-6">
                <input type="hidden" name="mode" value="decrypt">

                <div class="space-y-2">
                    <label for="encrypted_file" class="block text-sm font-medium text-gray-700">1. Upload Encrypted File (.enc)</label>
                    <input type="file" name="encrypted_file" id="encrypted_file" required class="w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-red-50 file:text-red-700 hover:file:bg-red-100 cursor-pointer">
                </div>

                <div class="space-y-2">
                    <label for="key_protector" class="block text-sm font-medium text-gray-700">2. Upload Key Protector File (.json)</label>
                    <input type="file" name="key_protector" id="key_protector" required class="w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-yellow-50 file:text-yellow-700 hover:file:bg-yellow-100 cursor-pointer">
                </div>

                <div class="space-y-2">
                    <label for="password_dec" class="block text-sm font-medium text-gray-700">3. Enter Password</label>
                    <input type="password" name="password" id="password_dec" required minlength="8" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500">
                </div>
                <div class="space-y-2">
                    <label for="password_confirm_dec" class="block text-sm font-medium text-gray-700">4. Confirm Password</label>
                    <input type="password" name="password_confirm" id="password_confirm_dec" required minlength="8" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500">
                </div>


                <button type="submit" class="w-full py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 transition duration-150 ease-in-out">
                    Decrypt File
                </button>
            </form>
        </div>

        <!-- DOWNLOAD SECTION -->
        <?php if ($downloadFile): ?>
            <div class="mt-8 pt-6 border-t border-gray-200">
                <h2 class="text-xl font-semibold mb-4 text-gray-800">Download Results</h2>
                <div class="space-y-3">
                    <?php if (isset($downloadFile['encryptedFile'])): ?>
                        <div class="flex items-center justify-between p-3 bg-gray-100 rounded-lg">
                            <span class="text-gray-700 font-mono text-sm"><?php echo $downloadFile['encryptedFile']; ?></span>
                            <a href="download.php?file=<?php echo urlencode($downloadFile['encryptedFile']); ?>" class="text-sm font-medium text-blue-600 hover:text-blue-800 transition duration-150 ease-in-out">
                                Download Encrypted File
                            </a>
                        </div>
                    <?php endif; ?>
                    <?php if (isset($downloadFile['keyFile'])): ?>
                        <div class="flex items-center justify-between p-3 bg-gray-100 rounded-lg border-2 border-dashed border-yellow-400">
                            <span class="text-gray-700 font-mono text-sm"><?php echo $downloadFile['keyFile']; ?></span>
                            <a href="download.php?file=<?php echo urlencode($downloadFile['keyFile']); ?>" class="text-sm font-medium text-yellow-600 hover:text-yellow-800 transition duration-150 ease-in-out">
                                Download Key Protector (CRITICAL!)
                            </a>
                        </div>
                    <?php endif; ?>
                    <?php if (isset($downloadFile['decryptedFile'])): ?>
                        <div class="flex items-center justify-between p-3 bg-gray-100 rounded-lg border-2 border-dashed border-green-400">
                            <!-- NEW: Shows the restored filename -->
                            <span class="text-gray-700 font-mono text-sm"><?php echo $downloadFile['decryptedFile']; ?></span>
                            <a href="download.php?file=<?php echo urlencode($downloadFile['decryptedFile']); ?>" class="text-sm font-medium text-green-600 hover:text-green-800 transition duration-150 ease-in-out">
                                Download Decrypted File
                            </a>
                        </div>
                    <?php endif; ?>
                </div>
                <p class="mt-4 text-sm text-red-600 font-semibold">
                    !!! IMPORTANT: Both the **Password** AND the **Key Protector file** are mandatory for decryption.
                </p>
            </div>
        <?php endif; ?>
    </div>

    <script>
        function switchTab(tab) {
            document.getElementById('tab-encrypt').classList.toggle('hidden', tab !== 'encrypt');
            document.getElementById('tab-decrypt').classList.toggle('hidden', tab !== 'decrypt');

            document.getElementById('tab-encrypt-btn').classList.toggle('active', tab === 'encrypt');
            document.getElementById('tab-decrypt-btn').classList.toggle('active', tab === 'decrypt');
        }

        // Set the active tab based on the form submission result or default to encrypt
        document.addEventListener('DOMContentLoaded', () => {
            const currentMode="<?php echo $_POST['mode'] ?? 'encrypt'; ?>";
            switchTab(currentMode);
        });
    </script>
</body>
</html>
PHP_APP_EOF
}

# Function to generate the PHP download handler (download.php)
generate_download_handler() {
    cat << 'DOWNLOAD_HANDLER_EOF' > "$DOWNLOAD_FILE"
<?php
// Configuration
$DATA_DIR=__DIR__ . '/data';

// Sanitize filename
$filename=basename($_GET['file'] ?? '');

if (empty($filename)) {
    http_response_code(400);
    die("File name not provided.");
}

$filepath=realpath("$DATA_DIR/$filename");

// Check if the file exists and is within the allowed data directory
if (!$filepath || !file_exists($filepath) || strpos($filepath, $DATA_DIR) !== 0) {
    http_response_code(404);
    die("File not found or access denied.");
}

// Set headers for download
header('Content-Description: File Transfer');
header('Content-Type: application/octet-stream');
// The $filename variable now contains the correct filename (either encrypted/key or decrypted/original)
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Expires: 0');
header('Cache-Control: must-revalidate');
header('Pragma: public');
header('Content-Length: ' . filesize($filepath));

// Clear output buffer and stream the file
ob_clean();
flush();
readfile($filepath);
exit;
?>
DOWNLOAD_HANDLER_EOF
}

# --- Script Execution ---

echo "Starting Hybrid Crypto Web App Setup..."

# 1. Dependency Checks
echo "Checking dependencies: php, openssl..."
check_dependency "php"
check_dependency "openssl"

# 2. Define web server user/group
WEB_USER="www-data" # Standard user for Apache/PHP-FPM

# 3. Directory Creation
echo "Creating web root directory: $WEB_ROOT"
mkdir -p "$WEB_ROOT"
mkdir -p "$DATA_DIR"
mkdir -p "$LOGS_DIR"
mkdir -p "$KEYS_DIR" # New directory for keys

# 4. Key Pair Generation (Hybrid RSA/PQC)
echo "--- Key Pair Generation Status ---"

# 4a. RSA 4096-bit (Standard Backup)
if [ ! -f "$PRIVATE_KEY_FILE" ]; then
    echo "Generating RSA 4096-bit private/public key pair (Fallback Key)..."
    openssl genpkey -algorithm RSA -out "$PRIVATE_KEY_FILE" -pkeyopt rsa_keygen_bits:4096 2>/dev/null
    openssl rsa -pubout -in "$PRIVATE_KEY_FILE" -out "$PUBLIC_KEY_FILE" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "Error generating RSA keys. Aborting."
        exit 1
    fi
    echo "RSA Keys generated successfully."
else
    echo "RSA Key pair already exists. Skipping RSA generation."
fi

# 4b. PQC Kyber Keys (Requires OQS-enabled OpenSSL)
if [ ! -f "$new_style_private_key" ]; then
    echo ""
    echo "Kyber PQC key pair missing. Kyber mode is currently disabled."
    echo "----------------------------------------------------------------------"
    echo "TO ENABLE QUANTUM-SAFE MODE (PQC):"
    echo "1. Install OpenSSL compiled with the Open Quantum Safe (OQS) provider."
    echo "2. Run the following commands to generate the raw binary keys required by the app:"
    echo '   # Generate PEM key (e.g., Kyber768 or Kyber1024):'
    echo '   openssl genpkey -algorithm Kyber768 -out KyberKey.pem'
    echo "   # Convert to raw binary format (.bin) required by PHP:"
    echo "   openssl pkey -in KyberKey.pem -outform DER -out $new_style_private_key"
    echo "   openssl pkey -in KyberKey.pem -pubout -outform DER -out $new_style_pub_key"
    echo "The application will automatically prioritize Kyber keys once they are available in $KEYS_DIR."
    echo "----------------------------------------------------------------------"
else
    echo "Kyber PQC key pair detected. PQC mode will be prioritized."
fi


# 5. Set Permissions (CRITICAL for security)
echo "Setting secure file permissions for the new path: $WEB_ROOT"

# Ownership: Everything should belong to the web user (www-data)
if id -u "$WEB_USER" >/dev/null 2>&1; then
    sudo chown -R $WEB_USER:$WEB_USER "$WEB_ROOT"
else
    echo "Warning: '$WEB_USER' user not found. Skipping ownership change."
fi

# Permissions on Directories
sudo chmod 755 "$WEB_ROOT"
sudo chmod 700 "$DATA_DIR" # Data directory only accessible by owner (www-data)
sudo chmod 700 "$LOGS_DIR" # Logs directory only accessible by owner (www-data)
sudo chmod 700 "$KEYS_DIR" # Keys directory only accessible by owner (www-data)

# Permissions on Key Files (Covers RSA and PQC)
echo "Setting restrictive permissions on all keys in $KEYS_DIR"
# Private Keys (RSA and PQC): Read-only for owner (www-data), NO access for group or others (600)
sudo chmod 600 "$PRIVATE_KEY_FILE"
sudo chmod 600 "$new_style_private_key" 2>/dev/null || true # Suppress error if file doesn't exist
# Public Keys (RSA and PQC): Read-only for owner (www-data), Read-only for group/others (644)
sudo chmod 644 "$PUBLIC_KEY_FILE"
sudo chmod 644 "$new_style_pub_key" 2>/dev/null || true # Suppress error if file doesn't exist

# 6. Generate PHP Files
echo "Generating index.php (Web App) with PQC fallback logic..."
generate_php_app

echo "Generating download.php (Secure Downloader)..."
generate_download_handler


echo "----------------------------------------------------------------------"
echo "Setup Complete!"
echo "The application is ready to use with RSA fallback, awaiting PQC keys."
echo "----------------------------------------------------------------------"
echo ""

# 7. Final Step: Restart Apache to ensure new permissions/files are loaded
sudo systemctl restart apache2

exit 0


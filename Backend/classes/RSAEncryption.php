<?php
require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../../vendor/autoload.php';

use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\PublicKeyLoader;

class RSAEncryption {
    
    /**
     * Encrypt AES key with RSA public key (SHA-256 OAEP)
     */
    public static function encryptAESKey($aes_key_raw, $public_key_pem) {
        try {
            // Decode base64 AES key to binary
            $aes_key_binary = base64_decode($aes_key_raw);
            
            if ($aes_key_binary === false) {
                throw new Exception("Failed to decode base64 AES key");
            }
            
            if (strlen($aes_key_binary) !== 32) {
                throw new Exception("Invalid AES key: must be 32 bytes (256 bits), got: " . strlen($aes_key_binary) . " bytes");
            }
            
            // ✅ Use phpseclib (NO openssl functions!)
            $publicKey = PublicKeyLoader::load($public_key_pem)
                ->withPadding(RSA::ENCRYPTION_OAEP)
                ->withHash('sha256')
                ->withMGFHash('sha256');
            
            // Encrypt with RSA-OAEP SHA-256
            $encrypted = $publicKey->encrypt($aes_key_binary);
            
            if (!$encrypted) {
                throw new Exception("RSA encryption returned empty result");
            }
            
            // Return base64 encoded
            return base64_encode($encrypted);
            
        } catch (Exception $e) {
            error_log("RSAEncryption::encryptAESKey error: " . $e->getMessage());
            error_log("Stack trace: " . $e->getTraceAsString());
            throw new Exception("Encryption error: " . $e->getMessage());
        }
    }
    
    /**
     * Get user's public key from database
     */
    public static function getUserPublicKey($user_id) {
        try {
            $database = new Database();
            $conn = $database->getConnection();
            
            $query = "SELECT public_key FROM users WHERE id = :user_id";
            $stmt = $conn->prepare($query);
            $stmt->bindParam(':user_id', $user_id);
            $stmt->execute();
            
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$result || empty($result['public_key'])) {
                throw new Exception("User public key not found. User must setup encryption first.");
            }
            
            return $result['public_key'];
            
        } catch (Exception $e) {
            error_log("RSAEncryption::getUserPublicKey error: " . $e->getMessage());
            throw $e;
        }
    }
}
?>
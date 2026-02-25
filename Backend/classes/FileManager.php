<?php
require_once __DIR__ . '/../config/db.php';

class FileManager {
    private $conn;
    private $table_files = "files";
    private $table_shares = "file_shares";
    private $upload_dir = __DIR__ . '/../uploads/';

    public function __construct() {
        $database = new Database();
        $this->conn = $database->getConnection();
        
        if (!file_exists($this->upload_dir)) {
            mkdir($this->upload_dir, 0777, true);
        }
    }

    /**
     * Get all files for a user
     * ✅ NO CHANGES NEEDED
     */
    public function getUserFiles($user_id) {
        try {
            $query = "SELECT id, original_filename, encrypted_filename, file_size, 
                             upload_date, file_hash 
                      FROM " . $this->table_files . " 
                      WHERE user_id = :user_id AND is_deleted = 0
                      ORDER BY upload_date DESC";
            
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":user_id", $user_id);
            $stmt->execute();

            $files = $stmt->fetchAll(PDO::FETCH_ASSOC);

            return ['success' => true, 'files' => $files];

        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Error: ' . $e->getMessage(), 'files' => []];
        }
    }

    /**
     * Get files shared with user
     * ✅ FIXED: owner_id -> shared_by
     * ✅ FIXED: shared_with_user_id -> shared_with
     * ✅ FIXED: Added encrypted_aes_key to SELECT
     */
    public function getSharedFiles($user_id) {
        try {
            $query = "SELECT f.id, f.original_filename, f.file_size, 
                             f.upload_date, u.username as owner_username,
                             s.share_date, s.can_download, s.expires_at,
                             s.encrypted_aes_key
                      FROM " . $this->table_shares . " s
                      JOIN " . $this->table_files . " f ON s.file_id = f.id
                      JOIN users u ON s.shared_by = u.id
                      WHERE s.shared_with = :user_id 
                      AND s.is_revoked = 0
                      AND f.is_deleted = 0
                      AND (s.expires_at IS NULL OR s.expires_at > NOW())
                      ORDER BY s.share_date DESC";
            
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":user_id", $user_id);
            $stmt->execute();

            $files = $stmt->fetchAll(PDO::FETCH_ASSOC);

            return ['success' => true, 'shared_files' => $files];

        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Error: ' . $e->getMessage(), 'shared_files' => []];
        }
    }

    /**
     * Upload new file
     * ✅ FIXED: encrypted_key -> aes_key_raw (column name)
     * ✅ FIXED: Parameter renamed $encrypted_key -> $aes_key_raw
     * ✅ FIXED: Removed dummy key generation
     */
    public function uploadFile($user_id, $file, $aes_key_raw = '') {
        try {
            if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
                return ['success' => false, 'message' => 'No file uploaded'];
            }

            $original_filename = basename($file['name']);
            $file_size = $file['size'];
            
            $encrypted_filename = uniqid() . '_' . hash('sha256', $original_filename . time());
            $file_path = $this->upload_dir . $encrypted_filename;

            if (!move_uploaded_file($file['tmp_name'], $file_path)) {
                return ['success' => false, 'message' => 'Failed to save file'];
            }

            $file_hash = hash_file('sha256', $file_path);

            // ✅ FIXED: aes_key_raw instead of encrypted_key
            $query = "INSERT INTO " . $this->table_files . " 
                      (user_id, original_filename, encrypted_filename, file_path, 
                       file_size, file_hash, aes_key_raw) 
                      VALUES (:user_id, :original_filename, :encrypted_filename, 
                              :file_path, :file_size, :file_hash, :aes_key_raw)";
            
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":user_id", $user_id);
            $stmt->bindParam(":original_filename", $original_filename);
            $stmt->bindParam(":encrypted_filename", $encrypted_filename);
            $stmt->bindParam(":file_path", $file_path);
            $stmt->bindParam(":file_size", $file_size);
            $stmt->bindParam(":file_hash", $file_hash);
            $stmt->bindParam(":aes_key_raw", $aes_key_raw);
            $stmt->execute();

            $file_id = $this->conn->lastInsertId();

            return [
                'success'   => true,
                'message'   => 'File uploaded successfully',
                'file_id'   => $file_id,
                'filename'  => $original_filename,
                'file_hash' => $file_hash
            ];

        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Error: ' . $e->getMessage()];
        }
    }

    /**
     * Download file
     * ✅ FIXED: $file['encrypted_key'] -> $file['aes_key_raw']
     * ✅ FIXED: shared_with_user_id -> shared_with
     * ✅ FIXED: encrypted_key_for_recipient -> encrypted_aes_key
     * ✅ ADDED: is_owner flag for frontend to know which decrypt method to use
     */
    public function downloadFile($file_id, $user_id) {
        try {
            $query = "SELECT f.*, u.username as owner_username 
                      FROM " . $this->table_files . " f
                      LEFT JOIN users u ON f.user_id = u.id
                      WHERE f.id = :file_id 
                      AND f.is_deleted = 0";
            
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":file_id", $file_id);
            $stmt->execute();
            $file = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$file) {
                return ['success' => false, 'message' => 'File not found'];
            }

            $has_access    = false;
            $encrypted_key = null;
            $is_owner      = false;
            
            // ✅ Owner: return raw AES key directly (no RSA decryption needed on frontend)
            if ($file['user_id'] == $user_id) {
                $has_access    = true;
                $is_owner      = true;
                $encrypted_key = $file['aes_key_raw'];
            } else {
                // ✅ Recipient: return RSA-encrypted AES key (frontend decrypts with private key)
                $share_query = "SELECT encrypted_aes_key 
                               FROM " . $this->table_shares . " 
                               WHERE file_id = :file_id 
                               AND shared_with = :user_id
                               AND is_revoked = 0
                               AND (expires_at IS NULL OR expires_at > NOW())";
                
                $share_stmt = $this->conn->prepare($share_query);
                $share_stmt->bindParam(":file_id", $file_id);
                $share_stmt->bindParam(":user_id", $user_id);
                $share_stmt->execute();
                
                if ($share_stmt->rowCount() > 0) {
                    $share_data    = $share_stmt->fetch(PDO::FETCH_ASSOC);
                    $has_access    = true;
                    $encrypted_key = $share_data['encrypted_aes_key'];
                }
            }

            if (!$has_access) {
                return ['success' => false, 'message' => 'Access denied'];
            }

            if (!file_exists($file['file_path'])) {
                return ['success' => false, 'message' => 'File not found on server'];
            }

            // Update last accessed
            $update = "UPDATE " . $this->table_files . " SET last_accessed = NOW() WHERE id = :file_id";
            $update_stmt = $this->conn->prepare($update);
            $update_stmt->bindParam(":file_id", $file_id);
            $update_stmt->execute();

            return [
                'success'   => true,
                'file_data' => [
                    'id'                => $file['id'],
                    'original_filename' => $file['original_filename'],
                    'file_size'         => $file['file_size'],
                    'file_hash'         => $file['file_hash'],
                    'encrypted_key'     => $encrypted_key,
                    'is_owner'          => $is_owner,
                    'is_encrypted'      => !empty($encrypted_key),
                    'file_path'         => $file['file_path'],
                    'owner'             => $file['owner_username']
                ]
            ];

        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Error: ' . $e->getMessage()];
        }
    }

    /**
     * Delete file (soft delete)
     * ✅ NO CHANGES NEEDED
     */
    public function deleteFile($file_id, $user_id) {
        try {
            $query = "SELECT * FROM " . $this->table_files . " 
                      WHERE id = :file_id AND user_id = :user_id AND is_deleted = 0";
            
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":file_id", $file_id);
            $stmt->bindParam(":user_id", $user_id);
            $stmt->execute();

            $file = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$file) {
                return ['success' => false, 'message' => 'File not found'];
            }

            $query = "UPDATE " . $this->table_files . " SET is_deleted = 1 WHERE id = :file_id";
            $stmt  = $this->conn->prepare($query);
            $stmt->bindParam(":file_id", $file_id);
            $stmt->execute();

            return ['success' => true, 'message' => 'File deleted successfully'];

        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Error: ' . $e->getMessage()];
        }
    }

    /**
     * Get deleted files (Bin)
     * ✅ NO CHANGES NEEDED
     */
    public function getDeletedFiles($user_id) {
        try {
            $query = "SELECT id, original_filename, file_size, upload_date
                      FROM " . $this->table_files . "
                      WHERE user_id = :user_id AND is_deleted = 1
                      ORDER BY upload_date DESC";

            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":user_id", $user_id);
            $stmt->execute();

            $files = $stmt->fetchAll(PDO::FETCH_ASSOC);

            return ['success' => true, 'deleted_files' => $files];

        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Error: ' . $e->getMessage(), 'deleted_files' => []];
        }
    }

    /**
     * Restore file from bin
     * ✅ NO CHANGES NEEDED
     */
    public function restoreFile($file_id, $user_id) {
        try {
            $query = "UPDATE " . $this->table_files . "
                      SET is_deleted = 0
                      WHERE id = :file_id AND user_id = :user_id AND is_deleted = 1";

            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":file_id", $file_id);
            $stmt->bindParam(":user_id", $user_id);
            $stmt->execute();

            if ($stmt->rowCount() === 0) {
                return ['success' => false, 'message' => 'File not found in bin'];
            }

            return ['success' => true, 'message' => 'File restored successfully'];

        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Error: ' . $e->getMessage()];
        }
    }

    /**
     * Permanently delete file from bin
     * ✅ NO CHANGES NEEDED
     */
    public function permanentDeleteFile($file_id, $user_id) {
        try {
            $query = "SELECT file_path FROM " . $this->table_files . "
                      WHERE id = :file_id AND user_id = :user_id AND is_deleted = 1";

            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":file_id", $file_id);
            $stmt->bindParam(":user_id", $user_id);
            $stmt->execute();

            $file = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$file) {
                return ['success' => false, 'message' => 'File not found in bin'];
            }

            if (file_exists($file['file_path'])) {
                unlink($file['file_path']);
            }

            $query = "DELETE FROM " . $this->table_shares . " WHERE file_id = :file_id";
            $stmt  = $this->conn->prepare($query);
            $stmt->bindParam(":file_id", $file_id);
            $stmt->execute();

            $query = "DELETE FROM " . $this->table_files . " WHERE id = :file_id AND user_id = :user_id";
            $stmt  = $this->conn->prepare($query);
            $stmt->bindParam(":file_id", $file_id);
            $stmt->bindParam(":user_id", $user_id);
            $stmt->execute();

            return ['success' => true, 'message' => 'File permanently deleted'];

        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Error: ' . $e->getMessage()];
        }
    }

    /**
     * Share file with another user
     * ✅ FIXED: Removed unused $encrypted_key_for_recipient parameter
     * ✅ FIXED: ON DUPLICATE KEY uses VALUES() - avoids PDO duplicate param binding error
     */
    public function shareFile($file_id, $user_id, $share_with_username) {
        try {
            // Get file and check ownership
            $query = "SELECT user_id, aes_key_raw FROM files WHERE id = :file_id AND is_deleted = 0";
            $stmt  = $this->conn->prepare($query);
            $stmt->bindParam(":file_id", $file_id);
            $stmt->execute();
            $file = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$file) {
                return ['success' => false, 'message' => 'File not found'];
            }
            
            if ($file['user_id'] != $user_id) {
                return ['success' => false, 'message' => 'You can only share your own files'];
            }
            
            // Get recipient
            $query = "SELECT id, public_key FROM users WHERE username = :username";
            $stmt  = $this->conn->prepare($query);
            $stmt->bindParam(":username", $share_with_username);
            $stmt->execute();
            $recipient = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$recipient) {
                return ['success' => false, 'message' => 'User not found'];
            }
            
            $recipient_id = $recipient['id'];
            
            if ($recipient_id == $user_id) {
                return ['success' => false, 'message' => 'Cannot share file with yourself'];
            }
            
            if (empty($recipient['public_key'])) {
                return ['success' => false, 'message' => 'Recipient has not set up encryption yet'];
            }
            
            // ✅ Encrypt AES key with recipient's RSA public key (backend PHP)
            require_once __DIR__ . '/RSAEncryption.php';
            $encrypted_aes_key = RSAEncryption::encryptAESKey(
                $file['aes_key_raw'],
                $recipient['public_key']
            );
            
            // ✅ FIXED: VALUES() in ON DUPLICATE KEY avoids duplicate PDO param binding
            $query = "INSERT INTO file_shares 
                      (file_id, shared_by, shared_with, encrypted_aes_key, share_date, can_download) 
                      VALUES (:file_id, :shared_by, :shared_with, :encrypted_aes_key, NOW(), 1)
                      ON DUPLICATE KEY UPDATE 
                      encrypted_aes_key = VALUES(encrypted_aes_key), 
                      can_download      = 1, 
                      is_revoked        = 0";
            
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":file_id",          $file_id);
            $stmt->bindParam(":shared_by",         $user_id);
            $stmt->bindParam(":shared_with",       $recipient_id);
            $stmt->bindParam(":encrypted_aes_key", $encrypted_aes_key);
            
            if ($stmt->execute()) {
                return [
                    'success' => true,
                    'message' => "File shared with {$share_with_username} successfully"
                ];
            } else {
                return ['success' => false, 'message' => 'Failed to create share record'];
            }
            
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Error: ' . $e->getMessage()];
        }
    }
}
?>

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
        
        // Create uploads directory if not exists
        if (!file_exists($this->upload_dir)) {
            mkdir($this->upload_dir, 0777, true);
        }
    }

    /**
     * Get all files for a user
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

            return [
                'success' => true,
                'files' => $files
            ];

        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => 'Error: ' . $e->getMessage(),
                'files' => []
            ];
        }
    }

    /**
     * Get files shared with user
     */
    public function getSharedFiles($user_id) {
        try {
            $query = "SELECT f.id, f.original_filename, f.encrypted_filename, f.file_size, 
                             f.upload_date, u.username as owner_username,
                             s.share_date, s.can_download, s.expires_at
                      FROM " . $this->table_shares . " s
                      JOIN " . $this->table_files . " f ON s.file_id = f.id
                      JOIN users u ON s.owner_id = u.id
                      WHERE s.shared_with_user_id = :user_id 
                      AND s.is_revoked = 0
                      AND f.is_deleted = 0
                      AND (s.expires_at IS NULL OR s.expires_at > NOW())
                      ORDER BY s.share_date DESC";
            
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":user_id", $user_id);
            $stmt->execute();

            $files = $stmt->fetchAll(PDO::FETCH_ASSOC);

            return [
                'success' => true,
                'shared_files' => $files
            ];

        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => 'Error: ' . $e->getMessage(),
                'shared_files' => []
            ];
        }
    }

    /**
     * Upload new file
     */
    public function uploadFile($user_id, $file, $encrypted_key = '') {
        try {
            // Validate file
            if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
                return ['success' => false, 'message' => 'No file uploaded'];
            }

            $original_filename = basename($file['name']);
            $file_size = $file['size'];
            
            // Generate unique encrypted filename
            $encrypted_filename = uniqid() . '_' . hash('sha256', $original_filename . time());
            $file_path = $this->upload_dir . $encrypted_filename;

            // Move uploaded file
            if (!move_uploaded_file($file['tmp_name'], $file_path)) {
                return ['success' => false, 'message' => 'Failed to save file'];
            }

            // Calculate file hash for integrity
            $file_hash = hash_file('sha256', $file_path);

            // Generate dummy encrypted key if not provided (for testing)
            if (empty($encrypted_key)) {
                $encrypted_key = base64_encode(random_bytes(32));
            }

            // Insert into database
            $query = "INSERT INTO " . $this->table_files . " 
                      (user_id, original_filename, encrypted_filename, file_path, 
                       file_size, encrypted_key, file_hash) 
                      VALUES (:user_id, :original_filename, :encrypted_filename, 
                              :file_path, :file_size, :encrypted_key, :file_hash)";
            
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":user_id", $user_id);
            $stmt->bindParam(":original_filename", $original_filename);
            $stmt->bindParam(":encrypted_filename", $encrypted_filename);
            $stmt->bindParam(":file_path", $file_path);
            $stmt->bindParam(":file_size", $file_size);
            $stmt->bindParam(":encrypted_key", $encrypted_key);
            $stmt->bindParam(":file_hash", $file_hash);
            $stmt->execute();

            $file_id = $this->conn->lastInsertId();

            return [
                'success' => true,
                'message' => 'File uploaded successfully',
                'file_id' => $file_id,
                'filename' => $original_filename,
                'file_hash' => $file_hash
            ];

        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => 'Error: ' . $e->getMessage()
            ];
        }
    }

    /**
     * Download file
     */
    public function downloadFile($file_id, $user_id) {
        try {
            // Check if user owns the file or has access
            $query = "SELECT f.* FROM " . $this->table_files . " f
                      LEFT JOIN " . $this->table_shares . " s 
                          ON f.id = s.file_id 
                          AND s.shared_with_user_id = :user_id
                          AND s.is_revoked = 0
                          AND (s.expires_at IS NULL OR s.expires_at > NOW())
                      WHERE f.id = :file_id 
                      AND f.is_deleted = 0
                      AND (f.user_id = :owner_id OR s.id IS NOT NULL)";
            
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":file_id", $file_id);
            $stmt->bindParam(":user_id", $user_id);
            $stmt->bindParam(":owner_id", $user_id);
            $stmt->execute();

            $file = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$file) {
                return ['success' => false, 'message' => 'File not found or access denied'];
            }

            if (!file_exists($file['file_path'])) {
                return ['success' => false, 'message' => 'File not found on server'];
            }

            // Update last accessed timestamp
            $update = "UPDATE " . $this->table_files . " 
                       SET last_accessed = NOW() 
                       WHERE id = :file_id";
            $stmt = $this->conn->prepare($update);
            $stmt->bindParam(":file_id", $file_id);
            $stmt->execute();

            return [
                'success' => true,
                'file' => $file
            ];

        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => 'Error: ' . $e->getMessage()
            ];
        }
    }

    /**
     * Delete file (soft delete)
     */
    public function deleteFile($file_id, $user_id) {
        try {
            // Get file info
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

            // Soft delete (set is_deleted flag)
            $query = "UPDATE " . $this->table_files . " 
                      SET is_deleted = 1 
                      WHERE id = :file_id";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":file_id", $file_id);
            $stmt->execute();

            return [
                'success' => true,
                'message' => 'File deleted successfully'
            ];

        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => 'Error: ' . $e->getMessage()
            ];
        }
    }

    /**
     * Share file with another user
     */
    public function shareFile($file_id, $owner_id, $share_with_username) {
        try {
            // Check if file exists and user is owner
            $query = "SELECT * FROM " . $this->table_files . " 
                      WHERE id = :file_id AND user_id = :owner_id AND is_deleted = 0";
            
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":file_id", $file_id);
            $stmt->bindParam(":owner_id", $owner_id);
            $stmt->execute();

            $file = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$file) {
                return ['success' => false, 'message' => 'File not found or you are not the owner'];
            }

            // Get recipient user ID
            $query = "SELECT id, username FROM users WHERE username = :username";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":username", $share_with_username);
            $stmt->execute();

            $recipient = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$recipient) {
                return ['success' => false, 'message' => 'User not found'];
            }

            if ($recipient['id'] == $owner_id) {
                return ['success' => false, 'message' => 'Cannot share file with yourself'];
            }

            // Check if already shared
            $query = "SELECT id FROM " . $this->table_shares . " 
                      WHERE file_id = :file_id 
                      AND owner_id = :owner_id 
                      AND shared_with_user_id = :recipient_id 
                      AND is_revoked = 0";
            
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":file_id", $file_id);
            $stmt->bindParam(":owner_id", $owner_id);
            $stmt->bindParam(":recipient_id", $recipient['id']);
            $stmt->execute();

            if ($stmt->rowCount() > 0) {
                return ['success' => false, 'message' => 'File already shared with this user'];
            }

            // Generate encrypted key for recipient (dummy for now)
            $encrypted_key_for_recipient = base64_encode(random_bytes(32));

            // Create share record
            $query = "INSERT INTO " . $this->table_shares . " 
                      (file_id, owner_id, shared_with_user_id, encrypted_key_for_recipient) 
                      VALUES (:file_id, :owner_id, :recipient_id, :encrypted_key)";
            
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":file_id", $file_id);
            $stmt->bindParam(":owner_id", $owner_id);
            $stmt->bindParam(":recipient_id", $recipient['id']);
            $stmt->bindParam(":encrypted_key", $encrypted_key_for_recipient);
            $stmt->execute();

            return [
                'success' => true,
                'message' => 'File shared successfully',
                'shared_with' => $recipient['username']
            ];

        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => 'Error: ' . $e->getMessage()
            ];
        }
    }
}
?>
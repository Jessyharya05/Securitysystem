<?php
/**
 * Authentication Class
 * Handles: Register, Login, Logout, Session Management, Password Hashing
 */

require_once __DIR__ . '/../config/db.php';

class Auth {
    private $conn;
    private $table_users = "users";
    private $table_sessions = "sessions";
    private $table_logs = "audit_logs";

    public function __construct() {
        $database = new Database();
        $this->conn = $database->getConnection();
    }

    /**
     * REGISTER - Create new user account
     */
    public function register($username, $email, $password) {
        try {
            // Validate input
            if (empty($username) || empty($email) || empty($password)) {
                return ['success' => false, 'message' => 'All fields are required'];
            }

            // Validate email format
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                return ['success' => false, 'message' => 'Invalid email format'];
            }

            // Password strength check (minimum 8 characters)
            if (strlen($password) < 8) {
                return ['success' => false, 'message' => 'Password must be at least 8 characters'];
            }

            // Check if username already exists
            $query = "SELECT id FROM " . $this->table_users . " WHERE username = :username";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":username", $username);
            $stmt->execute();

            if ($stmt->rowCount() > 0) {
                return ['success' => false, 'message' => 'Username already exists'];
            }

            // Check if email already exists
            $query = "SELECT id FROM " . $this->table_users . " WHERE email = :email";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":email", $email);
            $stmt->execute();

            if ($stmt->rowCount() > 0) {
                return ['success' => false, 'message' => 'Email already registered'];
            }

            // Hash password using bcrypt
            $password_hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

            // Insert new user
            $query = "INSERT INTO " . $this->table_users . " 
                      (username, email, password_hash) 
                      VALUES (:username, :email, :password_hash)";
            
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":username", $username);
            $stmt->bindParam(":email", $email);
            $stmt->bindParam(":password_hash", $password_hash);

            if ($stmt->execute()) {
                $user_id = $this->conn->lastInsertId();
                
                // Log the registration
                $this->logAction($user_id, 'USER_REGISTERED', "User registered: $username");

                return [
                    'success' => true, 
                    'message' => 'Registration successful',
                    'user_id' => $user_id
                ];
            } else {
                return ['success' => false, 'message' => 'Registration failed'];
            }

        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Error: ' . $e->getMessage()];
        }
    }

    /**
     * LOGIN - Authenticate user and create session
     */
    /**
 * LOGIN - Authenticate user and create session
 */
public function login($username, $password) {
    try {
        // Validate input
        if (empty($username) || empty($password)) {
            return ['success' => false, 'message' => 'Username and password required'];
        }

        // Get user from database - FIX: bind username twice
        $query = "SELECT id, username, email, password_hash, public_key 
                  FROM " . $this->table_users . " 
                  WHERE username = :username OR email = :email";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":username", $username);
        $stmt->bindParam(":email", $username); // bind to same value
        $stmt->execute();

        if ($stmt->rowCount() == 0) {
            return ['success' => false, 'message' => 'Invalid credentials'];
        }

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        // Verify password
        if (!password_verify($password, $user['password_hash'])) {
            // Log failed login attempt
            $this->logAction($user['id'], 'LOGIN_FAILED', "Failed login attempt for: $username");
            return ['success' => false, 'message' => 'Invalid credentials'];
        }

        // Create session
        $session_token = $this->createSession($user['id']);

        // Log successful login
        $this->logAction($user['id'], 'LOGIN_SUCCESS', "User logged in: $username");

        return [
            'success' => true,
            'message' => 'Login successful',
            'session_token' => $session_token,
            'user' => [
                'id' => $user['id'],
                'username' => $user['username'],
                'email' => $user['email'],
                'has_keys' => !empty($user['public_key'])
            ]
        ];

    } catch (Exception $e) {
        return ['success' => false, 'message' => 'Error: ' . $e->getMessage()];
    }
}

    /**
     * CREATE SESSION - Generate and store session token
     */
    private function createSession($user_id) {
        // Generate secure random session token
        $session_token = bin2hex(random_bytes(32));
        
        // Session expires in 24 hours
        $expires_at = date('Y-m-d H:i:s', strtotime('+24 hours'));
        
        // Get client info
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

        // Insert session
        $query = "INSERT INTO " . $this->table_sessions . " 
                  (user_id, session_token, ip_address, user_agent, expires_at) 
                  VALUES (:user_id, :session_token, :ip_address, :user_agent, :expires_at)";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":user_id", $user_id);
        $stmt->bindParam(":session_token", $session_token);
        $stmt->bindParam(":ip_address", $ip_address);
        $stmt->bindParam(":user_agent", $user_agent);
        $stmt->bindParam(":expires_at", $expires_at);
        $stmt->execute();

        return $session_token;
    }

    /**
     * VERIFY SESSION - Check if session token is valid
     */
    public function verifySession($session_token) {
        try {
            if (empty($session_token)) {
                return ['valid' => false, 'message' => 'No session token provided'];
            }

            $query = "SELECT s.*, u.id as user_id, u.username, u.email 
                      FROM " . $this->table_sessions . " s
                      JOIN " . $this->table_users . " u ON s.user_id = u.id
                      WHERE s.session_token = :session_token 
                      AND s.is_active = 1 
                      AND s.expires_at > NOW()";
            
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":session_token", $session_token);
            $stmt->execute();

            if ($stmt->rowCount() == 0) {
                return ['valid' => false, 'message' => 'Invalid or expired session'];
            }

            $session = $stmt->fetch(PDO::FETCH_ASSOC);

            return [
                'valid' => true,
                'user' => [
                    'id' => $session['user_id'],
                    'username' => $session['username'],
                    'email' => $session['email']
                ]
            ];

        } catch (Exception $e) {
            return ['valid' => false, 'message' => 'Error: ' . $e->getMessage()];
        }
    }

    /**
     * LOGOUT - Invalidate session
     */
    public function logout($session_token) {
        try {
            // Get user_id before logout for logging
            $verify = $this->verifySession($session_token);
            
            // Deactivate session
            $query = "UPDATE " . $this->table_sessions . " 
                      SET is_active = 0 
                      WHERE session_token = :session_token";
            
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":session_token", $session_token);
            $stmt->execute();

            // Log logout
            if ($verify['valid']) {
                $this->logAction($verify['user']['id'], 'LOGOUT', "User logged out");
            }

            return ['success' => true, 'message' => 'Logged out successfully'];

        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Error: ' . $e->getMessage()];
        }
    }

    /**
     * LOG ACTION - Record user actions for audit
     */
    private function logAction($user_id, $action, $details = '') {
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        
        $query = "INSERT INTO " . $this->table_logs . " 
                  (user_id, action, details, ip_address) 
                  VALUES (:user_id, :action, :details, :ip_address)";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":user_id", $user_id);
        $stmt->bindParam(":action", $action);
        $stmt->bindParam(":details", $details);
        $stmt->bindParam(":ip_address", $ip_address);
        $stmt->execute();
    }

    /**
     * GET USER BY ID
     */
    public function getUserById($user_id) {
        $query = "SELECT id, username, email, public_key, created_at 
                  FROM " . $this->table_users . " 
                  WHERE id = :user_id";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":user_id", $user_id);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            return $stmt->fetch(PDO::FETCH_ASSOC);
        }
        return null;
    }

    /**
     * UPDATE USER PUBLIC KEY (for RSA key storage)
     */
    public function updatePublicKey($user_id, $public_key) {
        $query = "UPDATE " . $this->table_users . " 
                  SET public_key = :public_key 
                  WHERE id = :user_id";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":public_key", $public_key);
        $stmt->bindParam(":user_id", $user_id);
        
        return $stmt->execute();
    }
}
?>
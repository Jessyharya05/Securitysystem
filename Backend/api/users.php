<?php
/**
 * API: User Management
 * GET /api/user.php - Get current user info
 * GET /api/user.php?username=bob - Get another user's public info
 * PUT /api/user.php - Update user info (public key)
 */

header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: GET, PUT, POST");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

require_once '../classes/auth.php';  // 

// Get session token from Authorization header
$headers = getallheaders();
$session_token = isset($headers['Authorization']) ? str_replace('Bearer ', '', $headers['Authorization']) : null;

if (!$session_token) {
    http_response_code(401);
    echo json_encode([
        "success" => false,
        "message" => "Unauthorized: No session token"
    ]);
    exit();
}

// Verify session
$auth = new Auth();
$session = $auth->verifySession($session_token);

if (!$session['valid']) {
    http_response_code(401);
    echo json_encode([
        "success" => false,
        "message" => "Unauthorized: Invalid session"
    ]);
    exit();
}

$user_id = $session['user']['id'];
$method = $_SERVER['REQUEST_METHOD'];

if ($method == 'GET') {
    // Check if requesting another user's info by username
    if (isset($_GET['username'])) {
        $username = $_GET['username'];
        
        // Get user by username (for getting public key when sharing)
        $target_user = $auth->getUserByUsername($username);
        
        if ($target_user) {
            // Only return public information (don't expose sensitive data)
            http_response_code(200);
            echo json_encode([
                "success" => true,
                "user" => [
                    "id" => $target_user['id'],
                    "username" => $target_user['username'],
                    "email" => $target_user['email'],
                    "public_key" => $target_user['public_key'],
                    "has_keys" => !empty($target_user['public_key'])  // ✅ Fixed: calculate it
                ]
            ]);
        } else {
            http_response_code(404);
            echo json_encode([
                "success" => false,
                "message" => "User not found"
            ]);
        }
    } else {
        // Get current user's information
        $user = $auth->getUserById($user_id);
        
        if ($user) {
            http_response_code(200);
            echo json_encode([
                "success" => true,
                "user" => $user
            ]);
        } else {
            http_response_code(404);
            echo json_encode([
                "success" => false,
                "message" => "User not found"
            ]);
        }
    }
    
} elseif ($method == 'PUT' || $method == 'POST') {
    // Update user information (public key)
    $data = json_decode(file_get_contents("php://input"));
    
    if (!isset($data->public_key)) {
        http_response_code(400);
        echo json_encode([
            "success" => false,
            "message" => "Missing required field: public_key"
        ]);
        exit();
    }
    
    // Update public key
    $result = $auth->updatePublicKey($user_id, $data->public_key);
    
    if ($result) {
        http_response_code(200);
        echo json_encode([
            "success" => true,
            "message" => "Public key updated successfully"
        ]);
    } else {
        http_response_code(400);
        echo json_encode([
            "success" => false,
            "message" => "Failed to update public key"
        ]);
    }
    
} else {
    http_response_code(405);
    echo json_encode([
        "success" => false,
        "message" => "Method not allowed"
    ]);
}
?>
<?php
/**
 * API: Logout User
 * POST /api/logout.php
 */

header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

require_once '../classes/Auth.php';

// Get session token from Authorization header
$headers = getallheaders();
$session_token = isset($headers['Authorization']) ? str_replace('Bearer ', '', $headers['Authorization']) : null;

if (!$session_token) {
    http_response_code(400);
    echo json_encode([
        "success" => false,
        "message" => "No session token provided"
    ]);
    exit();
}

// Create Auth instance
$auth = new Auth();

// Logout user
$result = $auth->logout($session_token);

// Set response code
http_response_code(200);

// Return response
echo json_encode($result);
?>

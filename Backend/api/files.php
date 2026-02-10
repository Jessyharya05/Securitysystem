<?php
/**
 * API: Get User Files
 * GET /api/files.php
 */

header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: GET");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

require_once '../classes/Auth.php';
require_once '../classes/FileManager.php';

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

// Create FileManager instance
$fileManager = new FileManager();

// Get user's files
$result = $fileManager->getUserFiles($user_id);

// Get shared files
$shared_result = $fileManager->getSharedFiles($user_id);

// Combine results
$response = [
    'success' => true,
    'my_files' => $result['files'],
    'shared_with_me' => $shared_result['shared_files']
];

// Set response code
http_response_code(200);

// Return response
echo json_encode($response);
?>

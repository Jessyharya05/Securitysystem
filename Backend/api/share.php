<?php
/**
 * API: Share File with Another User
 * POST /api/share.php
 * Body: { "file_id": 1, "share_with_username": "john" }
 */

header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

require_once '../classes/auth.php';
require_once '../classes/FileManager.php';

// Get session token
$headers = getallheaders();
$session_token = isset($headers['Authorization']) ? str_replace('Bearer ', '', $headers['Authorization']) : null;

if (!$session_token) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Unauthorized: No session token']);
    exit();
}

// Verify session
$auth = new Auth();
$session = $auth->verifySession($session_token);

if (!$session['valid']) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Unauthorized: Invalid session']);
    exit();
}

$user_id = $session['user']['id'];

// Get POST data
$input = file_get_contents("php://input");
$data = json_decode($input);

// Validate input
if (!$data || !isset($data->file_id) || !isset($data->share_with_username)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Missing required fields: file_id, share_with_username']);
    exit();
}

$file_id = intval($data->file_id);
$share_with_username = $data->share_with_username;

// Share file
$fileManager = new FileManager();
$result = $fileManager->shareFile($file_id, $user_id, $share_with_username);

if ($result['success']) {
    http_response_code(201);
} else {
    http_response_code(400);
}

echo json_encode($result);
?>
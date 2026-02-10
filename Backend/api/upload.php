<?php
/**
 * API: Upload File
 * POST /api/upload.php
 */

header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

require_once '../classes/Auth.php';
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

// Check if file was uploaded
if (!isset($_FILES['file'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'No file uploaded']);
    exit();
}

// Get encrypted flag (optional)
$encrypted = isset($_POST['encrypted']) ? (bool)$_POST['encrypted'] : false;

// Upload file
$fileManager = new FileManager();
$result = $fileManager->uploadFile($user_id, $_FILES['file'], $encrypted);

if ($result['success']) {
    http_response_code(201); // Created
} else {
    http_response_code(500);
}

echo json_encode($result);
?>
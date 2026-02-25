<?php
/**
 * API: Upload Encrypted File
 * POST /api/upload.php
 * 
 * Expects:
 * - $_FILES['file'] - The encrypted file blob (IV + encrypted data)
 * - $_POST['aes_key'] - Raw AES key (base64 encoded)
 */

header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

require_once '../classes/auth.php';
require_once '../classes/FileManager.php';
require_once __DIR__ . '/../../vendor/autoload.php';

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

// ✅ Get RAW AES key (base64 encoded)
$aes_key_raw = isset($_POST['aes_key']) ? $_POST['aes_key'] : null;

if (empty($aes_key_raw)) {
    http_response_code(400);
    echo json_encode([
        'success' => false, 
        'message' => 'Missing aes_key. File must be encrypted before upload.'
    ]);
    exit();
}

// Upload encrypted file with raw AES key
$fileManager = new FileManager();
$result = $fileManager->uploadFile($user_id, $_FILES['file'], $aes_key_raw);

if ($result['success']) {
    http_response_code(201);
} else {
    http_response_code(500);
}

echo json_encode($result);
?>
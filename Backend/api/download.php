<?php
/**
 * API: Download File
 * GET /api/download.php?file_id=1
 */

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET");
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

// Get file_id from query string
$file_id = isset($_GET['file_id']) ? intval($_GET['file_id']) : 0;

if (!$file_id) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Missing file_id parameter']);
    exit();
}

// Get file
$fileManager = new FileManager();
$result = $fileManager->downloadFile($file_id, $user_id);

if (!$result['success']) {
    http_response_code(404);
    echo json_encode($result);
    exit();
}

$file = $result['file'];

// Check if file exists on disk
if (!file_exists($file['file_path'])) {
    http_response_code(404);
    echo json_encode(['success' => false, 'message' => 'File not found on server']);
    exit();
}

// Set headers for file download
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . $file['original_filename'] . '"');
header('Content-Length: ' . filesize($file['file_path']));
header('Cache-Control: no-cache, must-revalidate');
header('Pragma: public');

// Output file
readfile($file['file_path']);
exit();
?>
<?php
/**
 * API: Delete File
 * DELETE /api/delete.php
 * Support: Query string (?file_id=1) OR JSON body ({"file_id": 1})
 */

header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: DELETE");
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

// Get file_id from query string OR JSON body
$file_id = 0;

// Try query string first
if (isset($_GET['file_id'])) {
    $file_id = intval($_GET['file_id']);
} else {
    // Try JSON body
    $input = file_get_contents("php://input");
    $data = json_decode($input);
    if ($data && isset($data->file_id)) {
        $file_id = intval($data->file_id);
    }
}

if (!$file_id) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Missing required field: file_id']);
    exit();
}

// Delete file
$fileManager = new FileManager();
$result = $fileManager->deleteFile($file_id, $user_id);

if ($result['success']) {
    http_response_code(200);
} else {
    http_response_code(403);
}

echo json_encode($result);
?>
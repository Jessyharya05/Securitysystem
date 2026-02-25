<?php
/**
 * API: Delete File
 * DELETE  /api/delete.php              → soft delete file
 * GET     /api/delete.php              → get deleted files (bin)
 * POST    /api/delete.php              → restore file
 * DELETE  /api/delete.php?permanent=1  → permanent delete
 */

header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: GET, DELETE, POST");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

require_once '../classes/auth.php';  // 
require_once '../classes/FileManager.php';

// Verify session
$headers = getallheaders();
$session_token = isset($headers['Authorization'])
    ? str_replace('Bearer ', '', $headers['Authorization'])
    : null;

if (!$session_token) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit();
}

$auth = new Auth();
$session = $auth->verifySession($session_token);

if (!$session['valid']) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Invalid session']);
    exit();
}

$user_id = $session['user']['id'];
$fileManager = new FileManager();
$method = $_SERVER['REQUEST_METHOD'];

// ── GET → Get deleted files (bin) ──────────────────────────────────
if ($method === 'GET') {
    $result = $fileManager->getDeletedFiles($user_id);
    echo json_encode($result);
    exit();
}

// ── POST → Restore file ──────────────────────────────────────
if ($method === 'POST') {
    $input = json_decode(file_get_contents("php://input"));
    $file_id = isset($input->file_id) ? intval($input->file_id) : 0;

    if (!$file_id) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Missing file_id']);
        exit();
    }

    $result = $fileManager->restoreFile($file_id, $user_id);
    echo json_encode($result);
    exit();
}

// ── DELETE → Soft delete OR permanent delete ───────────────
if ($method === 'DELETE') {
    $input = json_decode(file_get_contents("php://input"));
    $file_id = 0;

    if (isset($_GET['file_id'])) {
        $file_id = intval($_GET['file_id']);
    } elseif ($input && isset($input->file_id)) {
        $file_id = intval($input->file_id);
    }

    if (!$file_id) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Missing file_id']);
        exit();
    }

    // Permanent delete if flag ?permanent=1
    if (isset($_GET['permanent']) && $_GET['permanent'] == 1) {
        $result = $fileManager->permanentDeleteFile($file_id, $user_id);
    } else {
        // Normal soft delete → move to bin
        $result = $fileManager->deleteFile($file_id, $user_id);
    }

    http_response_code($result['success'] ? 200 : 403);
    echo json_encode($result);
    exit();
}

http_response_code(405);
echo json_encode(['success' => false, 'message' => 'Method not allowed']);
?>
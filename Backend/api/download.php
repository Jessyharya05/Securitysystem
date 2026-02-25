<?php
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: GET");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

require_once '../classes/auth.php';
require_once '../classes/FileManager.php';
require_once __DIR__ . '/../../vendor/autoload.php';

$headers = getallheaders();
$session_token = isset($headers['Authorization']) ? str_replace('Bearer ', '', $headers['Authorization']) : null;

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
$file_id = isset($_GET['file_id']) ? intval($_GET['file_id']) : 0;

if (!$file_id) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Missing file_id']);
    exit();
}

try {
    $fileManager = new FileManager();
    $result = $fileManager->downloadFile($file_id, $user_id);

    if (!$result['success']) {
        http_response_code(404);
        echo json_encode($result);
        exit();
    }

    $file_data = $result['file_data'];

    if (!file_exists($file_data['file_path'])) {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'File not found on server']);
        exit();
    }

    $file_content = file_get_contents($file_data['file_path']);

    // ✅ CRITICAL: Key must be 'file_data' not 'file'!
    $file_content = file_get_contents($file_data['file_path']);

echo json_encode([
    'success' => true,
    'file_data' => [
        'id' => $file_data['id'],
        'original_filename' => $file_data['original_filename'],
        'encrypted_key' => $file_data['encrypted_key'],
        'is_owner' => $file_data['is_owner'],
        'is_encrypted' => $file_data['is_encrypted'],
        'encrypted_content' => base64_encode($file_content),  // ✅ ADD THIS!
        'owner' => $file_data['owner']
    ]
]);

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Download failed: ' . $e->getMessage()
    ]);
}
?>
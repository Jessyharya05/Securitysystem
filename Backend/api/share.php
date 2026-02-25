<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);

header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

require_once '../classes/auth.php';  
require_once '../classes/FileManager.php';
require_once __DIR__ . '/../../vendor/autoload.php';

use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\PublicKeyLoader;  // ✅ ADD THIS TOO!

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

$input = file_get_contents("php://input");
$data = json_decode($input);

if (!$data || !isset($data->file_id) || !isset($data->share_with_username)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Missing file_id or username']);
    exit();
}

$file_id = intval($data->file_id);
$share_with_username = $data->share_with_username;

error_log("Share attempt: file_id=$file_id, user_id=$user_id, recipient=$share_with_username");

try {
    $fileManager = new FileManager();
    $result = $fileManager->shareFile($file_id, $user_id, $share_with_username);
    
    error_log("Share result: " . json_encode($result));
    
    http_response_code($result['success'] ? 201 : 400);
    echo json_encode($result);
    
} catch (Exception $e) {
    error_log("Share exception: " . $e->getMessage());
    error_log("Stack trace: " . $e->getTraceAsString());
    
    http_response_code(500);
    echo json_encode([
        'success' => false, 
        'message' => 'Share failed: ' . $e->getMessage()
    ]);
}
?>
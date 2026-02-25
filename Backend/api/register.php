<?php
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

require_once '../classes/auth.php';

$input = file_get_contents("php://input");
$data = json_decode($input);

// Validate input
if (!$data || !isset($data->username) || !isset($data->email) || !isset($data->password)) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => 'Missing required fields: username, email, password'
    ]);
    exit();
}

// ✅ Get public key (optional for now, required for encryption)
$public_key = isset($data->public_key) ? $data->public_key : null;

if (empty($public_key)) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => 'Public key is required for encryption'
    ]);
    exit();
}

// Register user WITH public key
$auth = new Auth();
$result = $auth->register(
    $data->username,
    $data->email,
    $data->password,
    $public_key  // ✅ Pass public key
);

http_response_code($result['success'] ? 201 : 400);
echo json_encode($result);
?>
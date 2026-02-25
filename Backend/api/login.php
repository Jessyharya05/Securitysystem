<?php
/**
 * API: Login User
 * POST /api/login.php
 */

header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

require_once '../classes/auth.php';

// Get POST data
$input = file_get_contents("php://input");
$data = json_decode($input);

// Validate input
if (!$data || !isset($data->username) || !isset($data->password)) {
    http_response_code(400);
    echo json_encode([
        "success" => false,
        "message" => "Missing required fields: username, password"
    ]);
    exit();
}

// Create Auth instance
$auth = new Auth();

// Login user
$result = $auth->login(
    $data->username,
    $data->password
);

// Set response code
if ($result['success']) {
    http_response_code(200); // OK
} else {
    http_response_code(401); // Unauthorized
}

// Return response
echo json_encode($result);
?>
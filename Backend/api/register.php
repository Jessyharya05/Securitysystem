<?php
/**
 * API: Register User
 * POST /api/register.php
 */

header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

require_once '../classes/auth.php';

// Get POST data
$input = file_get_contents("php://input");
$data = json_decode($input);

// Debug: Uncomment these lines if you want to see what's being received
// echo "Received: " . $input . "\n";
// var_dump($data);

// Validate input
if (!$data || !isset($data->username) || !isset($data->email) || !isset($data->password)) {
    http_response_code(400);
    echo json_encode([
        "success" => false,
        "message" => "Missing required fields: username, email, password"
    ]);
    exit();
}

// Create Auth instance
$auth = new Auth();

// Register user
$result = $auth->register(
    $data->username,
    $data->email,
    $data->password
);

// Set response code
if ($result['success']) {
    http_response_code(201); // Created
} else {
    http_response_code(400); // Bad Request
}

// Return response
echo json_encode($result);
?>
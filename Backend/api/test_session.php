<?php
header("Content-Type: text/plain");

echo "=== SESSION DEBUG ===\n\n";

// Check Authorization header
$headers = getallheaders();
echo "1. All Headers:\n";
print_r($headers);
echo "\n\n";

echo "2. Authorization Header:\n";
echo isset($headers['Authorization']) ? $headers['Authorization'] : 'NOT SET';
echo "\n\n";

// Extract token
$auth_header = isset($headers['Authorization']) ? $headers['Authorization'] : '';
$token = str_replace('Bearer ', '', $auth_header);
echo "3. Extracted Token:\n";
echo $token;
echo "\n\n";

// Check in database
require_once '../classes/Auth.php';
$auth = new Auth();
$result = $auth->verifySession($token);

echo "4. Verification Result:\n";
print_r($result);
?>

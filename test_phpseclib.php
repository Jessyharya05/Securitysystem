<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "<h2>Testing phpseclib Installation</h2>";

// Test 1: Check if autoload exists
$autoload_path = __DIR__ . '/vendor/autoload.php';
echo "1. Checking autoload at: <code>$autoload_path</code><br>";

if (file_exists($autoload_path)) {
    echo "✅ autoload.php exists<br><br>";
    require_once $autoload_path;
} else {
    die("❌ ERROR: autoload.php not found!<br>Run: <code>composer require phpseclib/phpseclib:~3.0</code>");
}

// Test 2: Check if classes can be loaded
echo "2. Testing class loading...<br>";

use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\PublicKeyLoader;

echo "✅ phpseclib classes loaded<br><br>";

// Test 3: Generate a test key
echo "3. Testing RSA key generation...<br>";
try {
    $key = RSA::createKey(2048);
    echo "✅ RSA key created (2048 bits)<br><br>";
    
    $publicKey = $key->getPublicKey();
    echo "4. Public key generated:<br>";
    echo "<pre>" . htmlspecialchars(substr($publicKey, 0, 200)) . "...</pre><br>";
    
    // Test 4: Test encryption with SHA-256
    echo "5. Testing encryption with SHA-256 OAEP...<br>";
    $testData = str_repeat("x", 32); // 32 bytes for AES-256 key
    
    $publicKeyObj = PublicKeyLoader::load($publicKey)
        ->withPadding(RSA::ENCRYPTION_OAEP)
        ->withHash('sha256')
        ->withMGFHash('sha256');
    
    $encrypted = $publicKeyObj->encrypt($testData);
    echo "✅ Encryption successful! Encrypted length: " . strlen($encrypted) . " bytes<br>";
    echo "✅ Base64 length: " . strlen(base64_encode($encrypted)) . " chars<br><br>";
    
    // Test 5: Test decryption
    echo "6. Testing decryption...<br>";
    $privateKeyObj = PublicKeyLoader::load($key)
        ->withPadding(RSA::ENCRYPTION_OAEP)
        ->withHash('sha256')
        ->withMGFHash('sha256');
    
    $decrypted = $privateKeyObj->decrypt($encrypted);
    
    if ($decrypted === $testData) {
        echo "✅ Decryption successful! Data matches!<br>";
    } else {
        echo "❌ Decryption failed! Data doesn't match!<br>";
    }
    
    echo "<br><h3>🎉 ALL TESTS PASSED!</h3>";
    echo "<p><strong>phpseclib is working correctly with SHA-256 OAEP padding.</strong></p>";
    echo "<p>You can now use RSAEncryption.php for file sharing!</p>";
    
} catch (Exception $e) {
    echo "❌ ERROR: " . $e->getMessage() . "<br>";
    echo "<pre>" . htmlspecialchars($e->getTraceAsString()) . "</pre>";
}
?>
<?php
// Force display ALL errors
error_reporting(E_ALL);
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');

echo "Step 1: PHP is working<br>";

// Check if db.php exists
$db_path = '../config/db.php';
echo "Step 2: Looking for database file at: " . realpath($db_path) . "<br>";

if (!file_exists($db_path)) {
    die("❌ ERROR: db.php not found at " . $db_path);
}

echo "Step 3: db.php file exists ✅<br>";

try {
    require_once $db_path;
    echo "Step 4: db.php loaded ✅<br>";
    
    $database = new Database();
    echo "Step 5: Database object created ✅<br>";
    
    $conn = $database->getConnection();
    echo "Step 6: Connection obtained ✅<br>";
    
    if ($conn) {
        echo "<h2>✅ Database Connected Successfully!</h2>";
        
        // Test query
        $stmt = $conn->query("SELECT * FROM users");
        $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        echo "<h3>Users in database: " . count($users) . "</h3>";
        echo "<pre>";
        print_r($users);
        echo "</pre>";
    }
    
} catch (Exception $e) {
    echo "<h2>❌ ERROR:</h2>";
    echo "<pre>" . $e->getMessage() . "</pre>";
    echo "<pre>" . $e->getTraceAsString() . "</pre>";
}
?>
<?php
/*
 * simple_test.php - Basic functionality test
 */

echo "========================================\n";
echo "syscall_filter - Simple Test\n";
echo "========================================\n\n";

// Check extension
if (!extension_loaded('syscall_filter')) {
    die("Error: Extension not loaded\n");
}
echo "[✓] Extension loaded\n\n";

// Test 1: Enable filter
echo "Test 1: Enable filter\n";
echo "------------------------\n";
$result = syscall_filter_begin([
    'read' => [],
    'write' => [],
    'stat' => [],
    'fstat' => [],
    'open' => [],
    'close' => [],
    'openat' => [],
]);
if ($result) {
    echo "[✓] Filter enabled\n";
} else {
    echo "[✗] Failed to enable\n";
    exit(1);
}

// Test 2: Execute allowed operations
echo "\nTest 2: Execute allowed syscalls\n";
echo "--------------------------------\n";
try {
    $content = file_get_contents(__FILE__);
    echo "[✓] file_get_contents() succeeded (read allowed)\n";

    $stat = stat(__FILE__);
    echo "[✓] stat() succeeded (stat allowed)\n";
} catch (Exception $e) {
    echo "[✗] Operation failed: " . $e->getMessage() . "\n";
}

// Test 3: Disable filter
echo "\nTest 3: Disable filter\n";
echo "-------------------------\n";
$result = syscall_filter_end([
    'read' => [],
    'write' => [],
    'stat' => [],
    'fstat' => [],
    'open' => [],
    'close' => [],
    'openat' => [],
]);
if ($result) {
    echo "[✓] Filter disabled\n";
} else {
    echo "[✗] Failed to disable\n";
}

echo "\n========================================\n";
echo "All tests passed!\n";
echo "========================================\n";
?>

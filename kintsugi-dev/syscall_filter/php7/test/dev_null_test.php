<?php
/*
 * dev_null_test.php - 测试 /dev/null 精确路径匹配
 */

echo "========================================\n";
echo "Test: /dev/null exact path matching\n";
echo "========================================\n\n";

// Check extension
if (!extension_loaded('syscall_filter')) {
    die("Error: Extension not loaded\n");
}
echo "[✓] Extension loaded\n\n";

// Test 1: 白名单包含 /dev/null (精确路径)
echo "Test 1: Whitelist with '/dev/null' (exact path)\n";
echo "------------------------------------------------\n";

$rules_exact = [
    'read' => [],
    'write' => [],
    'close' => [],
    'fstat' => [],
    'openat' => ['/dev/null'],  // 精确路径 (fopen用openat)
];

syscall_filter_begin($rules_exact);
echo "[*] Filter enabled with 'open' => ['/dev/null']\n";

$fp = @fopen('/dev/null', 'r');
if ($fp !== false) {
    echo "[✓] /dev/null ALLOWED (exact match)\n";
    fclose($fp);
} else {
    echo "[✗] /dev/null BLOCKED (exact match FAILED)\n";
}

syscall_filter_end($rules_exact);

// Test 2: 白名单包含 /dev/ (前缀路径)
echo "\nTest 2: Whitelist with '/dev/' (prefix path)\n";
echo "----------------------------------------------\n";

$rules_prefix = [
    'read' => [],
    'write' => [],
    'close' => [],
    'fstat' => [],
    'openat' => ['/dev/'],  // 前缀路径 (fopen用openat)
];

syscall_filter_begin($rules_prefix);
echo "[*] Filter enabled with 'open' => ['/dev/']\n";

$fp = @fopen('/dev/null', 'r');
if ($fp !== false) {
    echo "[✓] /dev/null ALLOWED (prefix match)\n";
    fclose($fp);
} else {
    echo "[✗] /dev/null BLOCKED (prefix match FAILED)\n";
}

syscall_filter_end($rules_prefix);

echo "\n========================================\n";
echo "Test Complete\n";
echo "========================================\n";
?>

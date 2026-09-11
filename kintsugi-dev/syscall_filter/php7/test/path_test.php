<?php
/*
 * path_test.php - Test path parameter whitelisting
 *
 * This test demonstrates the new path-based syscall filtering capability.
 * Syscalls can be constrained to specific path prefixes.
 *
 * Run with trace monitoring:
 *   sudo cat /sys/kernel/debug/tracing/trace_pipe
 */

echo "========================================\n";
echo "syscall_filter - Path Whitelist Test\n";
echo "========================================\n\n";

// Check extension
if (!extension_loaded('syscall_filter')) {
    die("Error: Extension not loaded\n");
}
echo "[✓] Extension loaded\n\n";

echo "Note: Monitor blocked syscalls with:\n";
echo "  sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n";

// Test 1: Path whitelist for openat
echo "Test 1: Path whitelist for openat\n";
echo "-------------------------------------\n";
echo "[*] Config: openat only allowed for /tmp/ and /etc/\n";

syscall_filter_begin([
    'write' => [],           // No path constraint
    'read' => [],            // No path constraint
    'close' => [],           // No path constraint
    'fstat' => [],           // No path constraint
    'openat' => ['/tmp/', '/etc/'],  // Path whitelist
]);

// Test allowed path: /tmp/
echo "\n[*] Testing allowed path: /tmp/\n";
file_put_contents('/tmp/test_allowed_12345', 'test content');
$fp = @fopen('/tmp/test_allowed_12345', 'r');
if ($fp !== false) {
    $content = fread($fp, 100);
    fclose($fp);
    echo "[✓] fopen('/tmp/test_allowed_12345') succeeded (expected - /tmp/ whitelisted)\n";
    @unlink('/tmp/test_allowed_12345');
} else {
    echo "[✗] fopen('/tmp/test_allowed_12345') failed (unexpected)\n";
}

// Test allowed path: /etc/
echo "\n[*] Testing allowed path: /etc/\n";
$fp = @fopen('/etc/hostname', 'r');
if ($fp !== false) {
    $content = fread($fp, 100);
    fclose($fp);
    echo "[✓] fopen('/etc/hostname') succeeded (expected - /etc/ whitelisted)\n";
} else {
    echo "[✗] fopen('/etc/hostname') failed (unexpected)\n";
}

// Test blocked path: /var/
echo "\n[*] Testing blocked path: /var/\n";
$fp = @fopen('/var/log/test_blocked_12345', 'r');
if ($fp === false) {
    echo "[✓] fopen('/var/log/test_blocked_12345') blocked (expected - /var/ not whitelisted)\n";
} else {
    fclose($fp);
    echo "[✗] fopen('/var/log/test_blocked_12345') succeeded (unexpected - should be blocked)\n";
}

// Test blocked path: current directory
echo "\n[*] Testing blocked path: current directory\n";
$fp = @fopen(__FILE__, 'r');
if ($fp === false) {
    echo "[✓] fopen(__FILE__) blocked (expected - current dir not whitelisted)\n";
} else {
    fclose($fp);
    echo "[✗] fopen(__FILE__) succeeded (unexpected - should be blocked)\n";
}

syscall_filter_end([
    'write' => [],
    'read' => [],
    'close' => [],
    'fstat' => [],
    'openat' => ['/tmp/', '/etc/'],
]);
echo "\n[✓] Filter disabled\n";

// Test 2: No path constraint (empty array)
echo "\n========================================\n";
echo "Test 2: No path constraint for openat\n";
echo "========================================\n";
echo "[*] Config: openat with empty array [] (no path constraint)\n";

syscall_filter_begin([
    'write' => [],
    'read' => [],
    'close' => [],
    'fstat' => [],
    'openat' => [],  // Empty array = no path constraint
]);

// All paths should be allowed now
echo "\n[*] Testing various paths (all should succeed)\n";

$fp = @fopen('/tmp/test_no_constraint_12345', 'w');
if ($fp !== false) {
    fwrite($fp, 'test');
    fclose($fp);
    echo "[✓] fopen('/tmp/...') succeeded (expected - no constraint)\n";
    @unlink('/tmp/test_no_constraint_12345');
} else {
    echo "[✗] fopen('/tmp/...') failed (unexpected)\n";
}

$fp = @fopen(__FILE__, 'r');
if ($fp !== false) {
    fclose($fp);
    echo "[✓] fopen(__FILE__) succeeded (expected - no constraint)\n";
} else {
    echo "[✗] fopen(__FILE__) failed (unexpected)\n";
}

syscall_filter_end([
    'write' => [],
    'read' => [],
    'close' => [],
    'fstat' => [],
    'openat' => [],
]);
echo "\n[✓] Filter disabled\n";

// Test 3: Multiple syscalls with different path constraints
echo "\n========================================\n";
echo "Test 3: Mixed path constraints\n";
echo "========================================\n";
echo "[*] Config:\n";
echo "    - openat: /tmp/ only\n";
echo "    - unlink: no paths (blocked entirely)\n";
echo "    - mkdir: /tmp/ and /var/tmp/\n";

syscall_filter_begin([
    'write' => [],
    'read' => [],
    'close' => [],
    'fstat' => [],
    'openat' => ['/tmp/'],           // Only /tmp/
    'unlink' => [],                  // No path constraint
    'mkdir' => ['/tmp/', '/var/tmp/'], // Two allowed paths
]);

// Test openat with /tmp/ (should succeed)
echo "\n[*] Testing openat with /tmp/ path\n";
$fp = @fopen('/tmp/test_mixed_12345', 'w');
if ($fp !== false) {
    fwrite($fp, 'test');
    fclose($fp);
    echo "[✓] fopen('/tmp/test_mixed_12345') succeeded (expected)\n";
} else {
    echo "[✗] fopen('/tmp/test_mixed_12345') failed (unexpected)\n";
}

// Test unlink (should succeed - no path constraint)
echo "\n[*] Testing unlink with no path constraint\n";
$result = @unlink('/tmp/test_mixed_12345');
if ($result === true) {
    echo "[✓] unlink('/tmp/test_mixed_12345') succeeded (expected - no constraint)\n";
} else {
    echo "[✗] unlink('/tmp/test_mixed_12345') failed (unexpected)\n";
}

// Test mkdir with /tmp/ (should succeed)
echo "\n[*] Testing mkdir with /tmp/ path\n";
$result = @mkdir('/tmp/test_dir_mixed_12345');
if ($result === true) {
    echo "[✓] mkdir('/tmp/test_dir_mixed_12345') succeeded (expected)\n";
    @rmdir('/tmp/test_dir_mixed_12345');
} else {
    echo "[✗] mkdir('/tmp/test_dir_mixed_12345') failed (unexpected)\n";
}

// Test mkdir with /var/tmp/ (should succeed)
echo "\n[*] Testing mkdir with /var/tmp/ path\n";
$result = @mkdir('/var/tmp/test_dir_mixed_12345');
if ($result === true) {
    echo "[✓] mkdir('/var/tmp/test_dir_mixed_12345') succeeded (expected)\n";
    @rmdir('/var/tmp/test_dir_mixed_12345');
} else {
    echo "[✗] mkdir('/var/tmp/test_dir_mixed_12345') failed (unexpected)\n";
}

// Test mkdir with /home/ (should be blocked)
echo "\n[*] Testing mkdir with /home/ path (not whitelisted)\n";
$result = @mkdir('/home/test_dir_blocked_12345');
if ($result === false) {
    echo "[✓] mkdir('/home/test_dir_blocked_12345') blocked (expected)\n";
} else {
    echo "[✗] mkdir('/home/test_dir_blocked_12345') succeeded (unexpected)\n";
    @rmdir('/home/test_dir_blocked_12345');
}

syscall_filter_end([
    'write' => [],
    'read' => [],
    'close' => [],
    'fstat' => [],
    'openat' => ['/tmp/'],
    'unlink' => [],
    'mkdir' => ['/tmp/', '/var/tmp/'],
]);
echo "\n[✓] Filter disabled\n";

// Test 4: Prefix matching behavior
echo "\n========================================\n";
echo "Test 4: Prefix matching verification\n";
echo "========================================\n";
echo "[*] Config: openat allowed for /tmp/ prefix\n";

syscall_filter_begin([
    'write' => [],
    'read' => [],
    'close' => [],
    'fstat' => [],
    'openat' => ['/tmp/'],
    'mkdir' => ['/tmp/'], 
    'unlink' => ['/tmp/'],  // 清理时需要
    'rmdir' => ['/tmp/'],   // 清理时需要
]);

// Test exact prefix match
echo "\n[*] Testing /tmp/file (should match /tmp/ prefix)\n";
file_put_contents('/tmp/test_prefix_12345', 'test');
$fp = @fopen('/tmp/test_prefix_12345', 'r');
if ($fp !== false) {
    fclose($fp);
    echo "[✓] /tmp/test_prefix_12345 matched (expected)\n";
    @unlink('/tmp/test_prefix_12345');
} else {
    echo "[✗] /tmp/test_prefix_12345 blocked (unexpected)\n";
}

// Test nested path
echo "\n[*] Testing /tmp/subdir/file (should match /tmp/ prefix)\n";
@mkdir('/tmp/test_subdir_12345');
file_put_contents('/tmp/test_subdir_12345/test', 'test');
$fp = @fopen('/tmp/test_subdir_12345/test', 'r');
if ($fp !== false) {
    fclose($fp);
    echo "[✓] /tmp/test_subdir_12345/test matched (expected)\n";
    @unlink('/tmp/test_subdir_12345/test');
    @rmdir('/tmp/test_subdir_12345');
} else {
    echo "[✗] /tmp/test_subdir_12345/test blocked (unexpected)\n";
}

// Test similar but non-matching path
echo "\n[*] Testing /tmpfile (should NOT match /tmp/ prefix)\n";
$fp = @fopen('/tmpfile_12345', 'w');
if ($fp === false) {
    echo "[✓] /tmpfile_12345 blocked (expected - doesn't match /tmp/ prefix)\n";
} else {
    fclose($fp);
    echo "[✗] /tmpfile_12345 allowed (unexpected)\n";
    @unlink('/tmpfile_12345');
}

syscall_filter_end([
    'write' => [],
    'read' => [],
    'close' => [],
    'fstat' => [],
    'openat' => ['/tmp/'],
]);
echo "\n[✓] Filter disabled\n";

echo "\n========================================\n";
echo "All path filtering tests complete!\n";
echo "========================================\n";
echo "\nCheck trace_pipe for detailed syscall events:\n";
echo "  sudo cat /sys/kernel/debug/tracing/trace_pipe\n";
?>

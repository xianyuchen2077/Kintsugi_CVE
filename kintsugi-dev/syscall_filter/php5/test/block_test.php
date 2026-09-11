<?php
/*
 * block_test.php - Test syscall blocking
 *
 * Run with trace monitoring:
 *   sudo cat /sys/kernel/debug/tracing/trace_pipe
 */

echo "========================================\n";
echo "syscall_filter - Block Test\n";
echo "========================================\n\n";

echo "Note: Monitor blocked syscalls with:\n";
echo "  sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n";

// Test 1: Allow specific file operations
echo "Test 1: Allow specific file operations\n";
echo "-------------------------------------\n";
// Note: Only syscalls in PRESET_SYSCALLS are monitored
// PRESET: open, openat, creat, close, read, write, pread64, pwrite64,
//         stat, fstat, lstat, chmod, chown, mkdir, rmdir,
//         unlink, unlinkat, rename, renameat, fork, vfork, clone,
//         execve, execveat, socket, connect, bind, listen, accept

// Create test file BEFORE enabling monitoring
file_put_contents('/tmp/test_file_12345', 'test');

syscall_filter_begin([
    'write' => [],
    'open' => [],      // PHP5 uses open (syscall 2)
    'read' => [],
    'close' => [],
    'fstat' => [],
]);
echo "[*] Whitelist: write, open, read, close, fstat\n";
echo "[*] Testing allowed operations...\n";

// Test allowed: openat + read
$fp = @fopen(__FILE__, 'r');
if ($fp !== false) {
    $content = fread($fp, 100);
    fclose($fp);
    echo "[✓] fopen/fread/fclose succeeded (expected - in whitelist)\n";
} else {
    echo "[✗] fopen failed (unexpected)\n";
}

echo "\n[*] Testing blocked operations...\n";

// Test blocked: unlink (not in whitelist)
$result = @unlink('/tmp/test_file_12345');
if ($result === false) {
    echo "[✓] unlink() blocked (expected - not in whitelist)\n";
} else {
    echo "[✗] unlink() succeeded (unexpected - should be blocked)\n";
}

// Test blocked: mkdir (not in whitelist)
$result = @mkdir('/tmp/test_dir_12345');
if ($result === false) {
    echo "[✓] mkdir() blocked (expected - not in whitelist)\n";
} else {
    echo "[✗] mkdir() succeeded (unexpected - should be blocked)\n";
    @rmdir('/tmp/test_dir_12345');
}

syscall_filter_end([
    'write' => [],
    'open' => [],
    'read' => [],
    'close' => [],
    'fstat' => [],
]);
echo "\n[✓] Filter disabled\n";

// Test 2: Block file operations
echo "\n========================================\n";
echo "Test 2: Block file read operations\n";
echo "========================================\n";
// Whitelist only write (for echo), block read/open
syscall_filter_begin([
    'write' => [],
]);
echo "[*] Whitelist: write only\n";
echo "[*] Testing blocked operation...\n";

$fp = @fopen(__FILE__, 'r');
if ($fp === false) {
    echo "[✓] fopen blocked (expected - open not in whitelist)\n";
} else {
    fclose($fp);
    echo "[✗] fopen succeeded (unexpected)\n";
}

syscall_filter_end([
    'write' => [],
]);
echo "\n[✓] Filter disabled\n";

// Test 3: Verify operations work after filter disabled
echo "\n========================================\n";
echo "Test 3: Operations after filter disabled\n";
echo "========================================\n";
echo "[*] Testing previously blocked operations...\n";

// Create test file again
file_put_contents('/tmp/test_file_after_12345', 'test');

// Now unlink should succeed (no filter active)
$result = @unlink('/tmp/test_file_after_12345');
if ($result === true) {
    echo "[✓] unlink() succeeded (expected - filter disabled)\n";
} else {
    echo "[✗] unlink() failed (unexpected - should work without filter)\n";
}

// mkdir should succeed (no filter active)
$result = @mkdir('/tmp/test_dir_after_12345');
if ($result === true) {
    echo "[✓] mkdir() succeeded (expected - filter disabled)\n";
    @rmdir('/tmp/test_dir_after_12345');
} else {
    echo "[✗] mkdir() failed (unexpected - should work without filter)\n";
}

// fopen should succeed (no filter active)
$fp = @fopen(__FILE__, 'r');
if ($fp !== false) {
    fclose($fp);
    echo "[✓] fopen() succeeded (expected - filter disabled)\n";
} else {
    echo "[✗] fopen() failed (unexpected - should work without filter)\n";
}

echo "\n========================================\n";
echo "Test Complete!\n";
echo "========================================\n";
echo "\nCheck trace_pipe for blocked syscalls:\n";
echo "  sudo cat /sys/kernel/debug/tracing/trace_pipe\n";
echo "Expected blocks: unlink (87), mkdir (83), open (2)\n";
?>

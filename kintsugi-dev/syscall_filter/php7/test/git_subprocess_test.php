<?php
/*
 * git_subprocess_test.php - 测试 Git 子进程 /dev/null 访问
 * 模拟 LLM 生成的修复代码场景
 */

echo "========================================\n";
echo "Test: Git subprocess /dev/null access\n";
echo "========================================\n\n";

// Check extension
if (!extension_loaded('syscall_filter')) {
    die("Error: Extension not loaded\n");
}
echo "[✓] Extension loaded\n\n";

// 模拟 LLM 的修复代码 - 只包含 open，不包含 openat
echo "Test 1: Simulate LLM repair (open only, no openat)\n";
echo "----------------------------------------------------\n";

$llm_repair_rules = [
    'read' => [],
    'write' => [],
    'close' => [],
    'fstat' => [],
    'stat' => [],
    'lstat' => [],
    'getpid' => [],
    'munmap' => [],
    'mmap' => [],
    'brk' => [],
    'clone' => [],
    'execve' => [],
    'wait4' => [],
    'dup2' => [],
    'pipe' => [],
    'fcntl' => [],

    // 只有 open，没有 openat
    'open' => ['/dev/null', '/lib/', '/etc/', '/usr/', '/var/', '/tmp/'],
];

syscall_filter_begin($llm_repair_rules);
echo "[*] Filter enabled (open only)\n\n";

echo "Executing: git --version 2>/dev/null\n";
$output = [];
$ret = 0;
exec('git --version 2>/dev/null', $output, $ret);

if ($ret === 0) {
    echo "[✓] Git executed successfully: " . implode("\n", $output) . "\n";
} else {
    echo "[✗] Git execution failed with exit code: $ret\n";
}

syscall_filter_end($llm_repair_rules);

// Test 2: 正确的修复 - 同时包含 open 和 openat
echo "\nTest 2: Correct repair (both open and openat)\n";
echo "------------------------------------------------\n";

$correct_rules = [
    'read' => [],
    'write' => [],
    'close' => [],
    'fstat' => [],
    'stat' => [],
    'lstat' => [],
    'getpid' => [],
    'munmap' => [],
    'mmap' => [],
    'brk' => [],
    'clone' => [],
    'execve' => [],
    'wait4' => [],
    'dup2' => [],
    'pipe' => [],
    'fcntl' => [],

    // 同时包含 open 和 openat
    'open' => ['/dev/null', '/lib/', '/etc/', '/usr/', '/var/', '/tmp/'],
    'openat' => ['/dev/null', '/lib/', '/etc/', '/usr/', '/var/', '/tmp/'],
];

syscall_filter_begin($correct_rules);
echo "[*] Filter enabled (open + openat)\n\n";

echo "Executing: git --version 2>/dev/null\n";
$output = [];
$ret = 0;
exec('git --version 2>/dev/null', $output, $ret);

if ($ret === 0) {
    echo "[✓] Git executed successfully: " . implode("\n", $output) . "\n";
} else {
    echo "[✗] Git execution failed with exit code: $ret\n";
}

syscall_filter_end($correct_rules);

echo "\n========================================\n";
echo "Test Complete\n";
echo "========================================\n";
?>

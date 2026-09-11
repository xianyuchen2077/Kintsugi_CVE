<?php
/**
 * net_filter PHP Test Script
 *
 * Test Contents:
 * 1. Access internal network without filtering
 * 2. Internal network blocked in external_only mode
 * 3. Normal connection restored after filter exit
 * 4. Internal network accessible in internal_only mode
 * 5. External network blocked in internal_only mode
 * 6. Whitelisted IP accessible in external_only + whitelist mode (additional config required)
 *
 * Whitelist Test:
 * - Set environment variable TEST_WHITELIST=1
 * - Pass internal IP as whitelist when running setup.sh
 */

require_once '/app/net_filter/net_filter.php';

define('INTERNAL_HOST', 'internal-api');
define('INTERNAL_PORT', 80);
define('EXTERNAL_HOST', 'example.com');
define('EXTERNAL_PORT', 80);
define('TEST_WHITELIST', getenv('TEST_WHITELIST') !== '0');

function test_connection($host, $port, $timeout = 3) {
    $socket = @fsockopen($host, $port, $errno, $errstr, $timeout);
    if ($socket) {
        fclose($socket);
        return true;
    }
    return false;
}

function run_tests() {
    echo str_repeat("=", 50) . "\n";
    echo "net_filter PHP Test\n";
    echo str_repeat("=", 50) . "\n";

    $passed = 0;
    $failed = 0;

    // Resolve internal IP
    $internal_ip = gethostbyname(INTERNAL_HOST);
    if ($internal_ip === INTERNAL_HOST) {
        echo "Error: Failed to resolve " . INTERNAL_HOST . "\n";
        return false;
    }
    echo "Internal Service IP: $internal_ip\n";

    // Test 1: No filter - Internal network accessible
    echo "\n[Test 1] No Filter - Internal network should be accessible\n";
    if (test_connection(INTERNAL_HOST, INTERNAL_PORT)) {
        echo "  ✓ Passed\n"; $passed++;
    } else {
        echo "  ✗ Failed\n"; $failed++;
    }

    // Test 2: external_only - Internal network blocked
    // Note: This test is mutually exclusive with Test 6, skip when whitelist is configured
    if (!TEST_WHITELIST) {
        echo "\n[Test 2] external_only - Internal network should be blocked\n";
        net_filter_begin(true);
        if (!test_connection(INTERNAL_HOST, INTERNAL_PORT, 2)) {
            echo "  ✓ Passed\n"; $passed++;
        } else {
            echo "  ✗ Failed (Internal network not blocked)\n"; $failed++;
        }
        net_filter_end();
    } else {
        echo "\n[Test 2] Skipped (Internal network not blocked in whitelist mode, see Test 6)\n";
    }

    // Test 3: Restored after exit
    echo "\n[Test 3] After Filter Exit - Internal network should be restored\n";
    if (test_connection(INTERNAL_HOST, INTERNAL_PORT)) {
        echo "  ✓ Passed\n"; $passed++;
    } else {
        echo "  ✗ Failed\n"; $failed++;
    }

    // Test 4: internal_only - Internal network accessible
    // Note: Use IP instead of hostname because DNS requests may be blocked
    echo "\n[Test 4] internal_only - Internal network should be accessible\n";
    net_filter_begin(false);
    if (test_connection($internal_ip, INTERNAL_PORT)) {
        echo "  ✓ Passed\n"; $passed++;
    } else {
        echo "  ✗ Failed\n"; $failed++;
    }
    net_filter_end();

    // Test 5: internal_only - External network blocked
    echo "\n[Test 5] internal_only - External network should be blocked\n";
    net_filter_begin(false);
    if (!test_connection(EXTERNAL_HOST, EXTERNAL_PORT, 2)) {
        echo "  ✓ Passed\n"; $passed++;
    } else {
        echo "  ✗ Failed (External network not blocked)\n"; $failed++;
    }
    net_filter_end();

    // Test 6: external_only + Whitelist - Whitelisted IP accessible
    if (TEST_WHITELIST) {
        echo "\n[Test 6] external_only + Whitelist - Internal network should be accessible (Whitelisted)\n";
        echo "  Note: Run setup.sh in whitelist mode first\n";
        net_filter_begin(true);
        if (test_connection(INTERNAL_HOST, INTERNAL_PORT, 2)) {
            echo "  ✓ Passed (Whitelisted IP not blocked)\n"; $passed++;
        } else {
            echo "  ✗ Failed (Whitelisted IP blocked)\n"; $failed++;
        }
        net_filter_end();
    } else {
        echo "\n[Test 6] Skipped (Set TEST_WHITELIST=1 to enable whitelist test)\n";
    }

    echo "\n" . str_repeat("=", 50) . "\n";
    echo "Result: $passed Passed, $failed Failed\n";
    echo str_repeat("=", 50) . "\n";

    return $failed === 0;
}

exit(run_tests() ? 0 : 1);
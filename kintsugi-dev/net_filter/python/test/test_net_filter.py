#!/usr/bin/env python3
"""
net_filter Python test script

Test cases:
1. Internal network accessible without filtering
2. Internal network blocked in external_only mode
3. Normal access restored after exiting 'with' block
4. Internal network accessible in internal_only mode
5. External network blocked in internal_only mode
6. Whitelisted IP accessible in external_only + whitelist mode (requires extra config)

Prerequisites:
- Host running: sudo ./setup.sh net-filter-python-test [Whitelisted IP]
- Container mounted: /sys/fs/cgroup:/sys/fs/cgroup:rw

Whitelist testing:
- Run: sudo ./setup.sh net-filter-python-test "$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' net-filter-python-internal)"
- This adds the internal-api IP to the whitelist
"""

import sys
import socket
import os

# Support two deployment methods: direct mount or build.sh deployment
sys.path.insert(0, '/tmp/python_net_filter')  # build.sh deployment path
sys.path.insert(0, '/app/net_filter')          # direct mount path
from net_filter import NetFilter

INTERNAL_HOST = "internal-api"
INTERNAL_PORT = 80
EXTERNAL_HOST = "example.com"
EXTERNAL_PORT = 80

# Environment variable to control whitelist mode testing (enabled by default)
TEST_WHITELIST = os.environ.get('TEST_WHITELIST', '1') == '1'

def test_connection(host, port, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except (socket.timeout, socket.error, OSError):
        return False

def run_tests():
    print("=" * 50)
    print("net_filter Python Test")
    print("=" * 50)

    passed = failed = 0

    # Resolve internal IP
    try:
        internal_ip = socket.gethostbyname(INTERNAL_HOST)
        print(f"Internal service IP: {internal_ip}")
    except socket.gaierror:
        print(f"Error: Could not resolve {INTERNAL_HOST}")
        return False

    # Test 1: No filtering - Internal accessible
    print("\n[Test 1] No filtering - Internal should be accessible")
    if test_connection(INTERNAL_HOST, INTERNAL_PORT):
        print("  ✓ Passed"); passed += 1
    else:
        print("  ✗ Failed"); failed += 1

    # Test 2: external_only - Internal blocked
    # Note: Mutually exclusive with Test 6, skip if whitelist is configured
    if not TEST_WHITELIST:
        print("\n[Test 2] external_only - Internal should be blocked")
        try:
            with NetFilter(external_only=True):
                if not test_connection(INTERNAL_HOST, INTERNAL_PORT, timeout=2):
                    print("  ✓ Passed"); passed += 1
                else:
                    print("  ✗ Failed (Internal not blocked)"); failed += 1
        except Exception as e:
            print(f"  ✗ Exception: {e}"); failed += 1
    else:
        print("\n[Test 2] Skipped (Internal not blocked in whitelist mode, see Test 6)")

    # Test 3: Restore after exit
    print("\n[Test 3] Exit 'with' block - Internal should be restored")
    if test_connection(INTERNAL_HOST, INTERNAL_PORT):
        print("  ✓ Passed"); passed += 1
    else:
        print("  ✗ Failed"); failed += 1

    # Test 4: internal_only - Internal accessible
    # Note: Use IP address instead of hostname as DNS requests might be blocked
    print("\n[Test 4] internal_only - Internal should be accessible")
    try:
        with NetFilter(internal_only=True):
            if test_connection(internal_ip, INTERNAL_PORT):
                print("  ✓ Passed"); passed += 1
            else:
                print("  ✗ Failed"); failed += 1
    except Exception as e:
        print(f"  ✗ Exception: {e}"); failed += 1

    # Test 5: internal_only - External blocked
    print("\n[Test 5] internal_only - External should be blocked")
    try:
        with NetFilter(internal_only=True):
            if not test_connection(EXTERNAL_HOST, EXTERNAL_PORT, timeout=2):
                print("  ✓ Passed"); passed += 1
            else:
                print("  ✗ Failed (External not blocked)"); failed += 1
    except Exception as e:
        print(f"  ✗ Exception: {e}"); failed += 1

    # Test 6: external_only + Whitelist - Whitelisted IP accessible
    # Only runs if TEST_WHITELIST=1 environment variable is set
    if TEST_WHITELIST:
        print("\n[Test 6] external_only + Whitelist - Internal should be accessible (Whitelisted)")
        print(f"  Note: Requires running setup.sh in whitelist mode first")
        try:
            with NetFilter(external_only=True):
                if test_connection(INTERNAL_HOST, INTERNAL_PORT, timeout=2):
                    print("  ✓ Passed (Whitelisted IP not blocked)"); passed += 1
                else:
                    print("  ✗ Failed (Whitelisted IP blocked)"); failed += 1
        except Exception as e:
            print(f"  ✗ Exception: {e}"); failed += 1
    else:
        print("\n[Test 6] Skipped (Set TEST_WHITELIST=1 to enable whitelist testing)")

    print("\n" + "=" * 50)
    print(f"Results: {passed} Passed, {failed} Failed")
    print("=" * 50)
    return failed == 0

if __name__ == "__main__":
    sys.exit(0 if run_tests() else 1)

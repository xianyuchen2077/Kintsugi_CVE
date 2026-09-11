#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Basic functionality tests for Python syscall_filter

Tests:
1. Module import
2. syscall_filter_begin/end with allowed operations
3. Blocking non-whitelisted syscalls
4. Reversibility (can enable/disable multiple times)
5. Context manager usage
"""

import sys
import subprocess

# Add module to path
sys.path.insert(0, '/tmp/python_syscall_filter')

from syscall_filter import (
    syscall_filter_begin,
    syscall_filter_end,
    SyscallFilter
)

def print_test(name):
    print(f"\n{'='*70}")
    print(f" {name}")
    print(f"{'='*70}")

def test_import():
    """Test 1: Module can be imported"""
    print_test("TEST 1: Module Import")
    try:
        import syscall_filter
        print(f"✓ Module imported successfully")
        print(f"  Version: {syscall_filter.__version__}")
        return True
    except Exception as e:
        print(f"✗ Import failed: {e}")
        return False

def test_basic_filter():
    """Test 2: Basic syscall filtering"""
    print_test("TEST 2: Basic Syscall Filtering")

    # Enable filter with file I/O syscalls (Protocol 4.0.0 - dict syntax)
    allowed = {
        'read': [],
        'write': [],
        'open': [],
        'openat': [],
        'close': [],
        'stat': [],
        'fstat': [],
        'lstat': []
    }
    print(f"Enabling filter with: {', '.join(allowed.keys())}")

    try:
        result = syscall_filter_begin(allowed)
        if not result:
            print("✗ syscall_filter_begin() returned False")
            print("  (This is expected if eBPF loader is not running)")
            return False
        print("✓ syscall_filter_begin() succeeded")
    except Exception as e:
        print(f"✗ syscall_filter_begin() failed: {e}")
        return False

    # Test allowed operation
    print("\nTesting allowed operation (file read)...")
    try:
        with open('/etc/hostname', 'r') as f:
            content = f.read().strip()
        print(f"✓ File read succeeded: {content}")
    except Exception as e:
        print(f"✗ File read failed: {e}")
        syscall_filter_end(allowed)
        return False

    # Disable filter
    print("\nDisabling filter...")
    try:
        result = syscall_filter_end(allowed)
        if not result:
            print("  Warning: syscall_filter_end() returned False")
        print("✓ syscall_filter_end() succeeded")
    except Exception as e:
        print(f"✗ syscall_filter_end() failed: {e}")
        return False

    return True

def test_block_execution():
    """Test 3: Block command execution"""
    print_test("TEST 3: Block Command Execution")

    # Enable filter (using minimal whitelist to block execve) - Protocol 4.0.0 dict syntax
    allowed = {
        'read': [],
        'write': [],
        'open': [],
        'openat': [],
        'close': []
    }
    print(f"Enabling filter (execve NOT in whitelist)...")

    try:
        syscall_filter_begin(allowed)
        print("✓ Filter enabled")
    except Exception as e:
        print(f"✗ Filter enable failed: {e}")
        return False

    # Try to execute a command (should fail)
    print("\nAttempting subprocess.run(['echo', 'test'])...")
    try:
        result = subprocess.run(['echo', 'test'], capture_output=True, text=True, timeout=2)
        print(f"✗ Command executed successfully (should have been blocked)")
        print(f"  Output: {result.stdout}")
        syscall_filter_end(allowed)
        return False
    except OSError as e:
        if e.errno == 1:  # EPERM
            print(f"✓ Command blocked with EPERM: {e}")
        else:
            print(f"? Command failed with unexpected error: {e}")
            syscall_filter_end(allowed)
            return False
    except subprocess.TimeoutExpired:
        print(f"? Command timed out (might be blocked)")
    except Exception as e:
        print(f"? Unexpected exception: {e}")

    # Disable filter
    print("\nDisabling filter...")
    try:
        syscall_filter_end(allowed)
        print("✓ Filter disabled")
    except Exception as e:
        print(f"✗ Filter disable failed: {e}")
        return False

    # Try command again (should work now)
    print("\nAttempting command again (should work now)...")
    try:
        result = subprocess.run(['echo', 'test'], capture_output=True, text=True, timeout=2)
        print(f"✓ Command executed after filter disabled: {result.stdout.strip()}")
    except Exception as e:
        print(f"✗ Command still failed: {e}")
        return False

    return True

def test_context_manager():
    """Test 4: Context manager usage"""
    print_test("TEST 4: Context Manager")

    print("Using SyscallFilter context manager (Protocol 4.0.0 - dict syntax)...")
    try:
        with SyscallFilter({'read': [], 'write': [], 'open': [], 'openat': [],
                           'close': [], 'stat': [], 'fstat': []}):
            print("✓ Entered context (filter active)")

            # Test allowed operation
            with open('/etc/hostname', 'r') as f:
                hostname = f.read().strip()
            print(f"✓ File read succeeded: {hostname}")

        print("✓ Exited context (filter disabled)")
    except Exception as e:
        print(f"✗ Context manager failed: {e}")
        return False

    return True

def test_reversibility():
    """Test 5: Reversibility (multiple enable/disable cycles)"""
    print_test("TEST 5: Reversibility")

    # Protocol 4.0.0 - dict syntax
    allowed = {
        'read': [],
        'write': [],
        'open': [],
        'openat': [],
        'close': []
    }

    print("Testing multiple enable/disable cycles...")
    for i in range(3):
        print(f"\nCycle {i+1}:")
        try:
            # Enable
            syscall_filter_begin(allowed)
            print(f"  ✓ Enabled")

            # Test operation
            with open('/etc/hostname', 'r') as f:
                _ = f.read()
            print(f"  ✓ File read works")

            # Disable
            syscall_filter_end(allowed)
            print(f"  ✓ Disabled")

        except Exception as e:
            print(f"  ✗ Cycle {i+1} failed: {e}")
            return False

    print("\n✓ All cycles completed successfully")
    return True

# ============================================================================
# Main test runner
# ============================================================================

def main():
    print("\n" + "="*70)
    print(" Python Syscall Filter - Basic Functionality Tests")
    print("="*70)

    results = {}

    # Run all tests
    results['import'] = test_import()
    results['basic_filter'] = test_basic_filter()
    results['block_execution'] = test_block_execution()
    results['context_manager'] = test_context_manager()
    results['reversibility'] = test_reversibility()

    # Summary
    print_test("TEST SUMMARY")
    passed = sum(results.values())
    total = len(results)

    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")

    print(f"\n{passed}/{total} tests passed")

    if passed == total:
        print("\n✓ All tests passed!")
        return 0
    else:
        print(f"\n✗ {total - passed} tests failed")
        print("\nNote: If eBPF loader is not running, all tests except import will fail.")
        print("Start eBPF loader on host: sudo python3 syscall_filter/ebpf_load.py &")
        return 1

if __name__ == '__main__':
    sys.exit(main())

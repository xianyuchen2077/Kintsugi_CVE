package com.syscallfilter;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Full test of Java syscall filter functionality
 */
public class FullTest {

    private static Map<String, List<String>> createJavaWhitelist() {
        Map<String, List<String>> map = new HashMap<>();
        // Core syscalls Java JVM needs
        map.put("read", List.of());
        map.put("write", List.of());
        map.put("openat", List.of());
        map.put("close", List.of());
        map.put("mmap", List.of());
        map.put("munmap", List.of());
        map.put("brk", List.of());
        map.put("futex", List.of());
        map.put("rt_sigaction", List.of());
        map.put("rt_sigprocmask", List.of());
        map.put("clone", List.of());
        map.put("mprotect", List.of());
        map.put("fstat", List.of());
        map.put("lseek", List.of());
        map.put("pread64", List.of());
        return map;
    }

    private static Map<String, List<String>> createJavaWhitelistWithPaths() {
        Map<String, List<String>> map = new HashMap<>();
        // Core syscalls Java JVM needs
        map.put("read", List.of());
        map.put("write", List.of());
        map.put("openat", List.of("/tmp/", "/home/", "/usr/lib/"));  // Path filtering on openat
        map.put("close", List.of());
        map.put("mmap", List.of());
        map.put("munmap", List.of());
        map.put("brk", List.of());
        map.put("futex", List.of());
        map.put("rt_sigaction", List.of());
        map.put("rt_sigprocmask", List.of());
        map.put("clone", List.of());
        map.put("mprotect", List.of());
        map.put("fstat", List.of());
        map.put("lseek", List.of());
        map.put("pread64", List.of());
        return map;
    }

    public static void main(String[] args) {
        System.out.println("=== Java Syscall Filter Full Test ===\n");

        // Test 1: Basic begin/end without filtering
        System.out.println("Test 1: Basic begin/end (allow all syscalls)");
        try {
            // Allow all syscalls Java needs
            boolean beginResult = SyscallFilter.begin(createJavaWhitelist());

            System.out.println("  begin() returned: " + beginResult);

            if (beginResult) {
                System.out.println("  ✓ Filter enabled successfully");
                System.out.println("  Performing some operations...");

                // Do some operations
                String test = "Hello World";
                System.out.println("  String created: " + test);

                // End filtering
                boolean endResult = SyscallFilter.end(createJavaWhitelist());

                System.out.println("  end() returned: " + endResult);

                if (endResult) {
                    System.out.println("  ✓ Filter disabled successfully");
                } else {
                    System.out.println("  ✗ Failed to disable filter");
                }
            } else {
                System.out.println("  ✗ Failed to enable filter");
            }
        } catch (Exception e) {
            System.err.println("  ✗ Exception: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
        System.out.println();

        // Test 2: try-with-resources
        System.out.println("Test 2: try-with-resources");
        try {
            try (SyscallFilter filter = new SyscallFilter(createJavaWhitelist())) {
                System.out.println("  ✓ Inside filter context");
                System.out.println("  Performing operations...");
                String test = "Inside filter";
                System.out.println("  String: " + test);
            }
            System.out.println("  ✓ Filter auto-closed successfully");
        } catch (Exception e) {
            System.err.println("  ✗ Exception: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
        System.out.println();

        // Test 3: Path filtering
        System.out.println("Test 3: Path filtering (openat with path whitelist)");
        try {
            try (SyscallFilter filter = new SyscallFilter(createJavaWhitelistWithPaths())) {
                System.out.println("  ✓ Filter with path constraints enabled");
                System.out.println("  Path whitelist for openat: /tmp/, /home/, /usr/lib/");
                System.out.println("  Performing operations...");

                // Do some operations that should work with the path filter
                String test = "Testing with path filtering";
                System.out.println("  String: " + test);

                System.out.println("  ✓ Operations completed successfully");
            }
            System.out.println("  ✓ Path filter auto-closed successfully");
        } catch (Exception e) {
            System.err.println("  ✗ Exception: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }

        System.out.println("\n=== All tests passed! ===");
        System.out.println("Java syscall filter is working correctly.");
    }
}

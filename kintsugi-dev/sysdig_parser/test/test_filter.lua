#!/usr/bin/env lua

-- Test script for filter.lua functionality
-- Mock sysdig environment and test event filtering logic

-- Add parent directory to Lua path for imports
package.path = package.path .. ";../?.lua"

local messagepack = require("MessagePack")

-- Mock sysdig environment
local mock_field_values = {}

-- Mock evt object  
evt = {
    field = function(handle)
        return mock_field_values[handle]
    end
}

-- Mock io.write to collect output
local captured_output = {}
local original_io_write = io.write
io.write = function(data)
    table.insert(captured_output, data)
end

-- Import functions from filter.lua
local filter = require("filter")
local should_capture_event = filter.should_capture_event

-- Test cases
local test_cases = {
    -- Test case 1: Valid container event (should pass)
    {
        name = "Valid container file event",
        data = {
            ["container.id"] = "container123",
            ["proc.name"] = "python",
            ["evt.category"] = "file",
            ["evt.type"] = "open",
            ["evt.arg.filename"] = "/tmp/test.txt"
        },
        expected = true
    },
    
    -- Test case 2: Host event (should be filtered out)
    {
        name = "Host event (filtered)",
        data = {
            ["container.id"] = "host", 
            ["proc.name"] = "python",
            ["evt.category"] = "file",
            ["evt.type"] = "open"
        },
        expected = false
    },
    
    -- Test case 3: Hypercorn process (should be filtered out)
    {
        name = "Hypercorn process (filtered)",
        data = {
            ["container.id"] = "container123",
            ["proc.name"] = "hypercorn",
            ["evt.category"] = "net", 
            ["evt.type"] = "accept"
        },
        expected = false
    },
    
    -- Test case 4: Excluded event type (should be filtered out)
    {
        name = "Excluded event type (filtered)",
        data = {
            ["container.id"] = "container123",
            ["proc.name"] = "python",
            ["evt.category"] = "file",
            ["evt.type"] = "stat"
        },
        expected = false
    },
    
    -- Test case 5: Invalid category (should be filtered out)
    {
        name = "Invalid category (filtered)",
        data = {
            ["container.id"] = "container123",
            ["proc.name"] = "python", 
            ["evt.category"] = "memory",
            ["evt.type"] = "mmap"
        },
        expected = false
    },
    
    -- Test case 6: IPC write event (should pass)
    {
        name = "Valid IPC write event",
        data = {
            ["container.id"] = "container123",
            ["proc.name"] = "python",
            ["evt.category"] = "ipc",
            ["evt.type"] = "write"
        },
        expected = true
    },
    
    -- Test case 7: Network event (should pass)
    {
        name = "Valid network event",
        data = {
            ["container.id"] = "container123",
            ["proc.name"] = "nginx",
            ["evt.category"] = "net",
            ["evt.type"] = "accept4"
        },
        expected = true
    }
}

-- Run tests
print("Running filter.lua tests...")
print("========================================")

local passed = 0
local failed = 0

for i, test_case in ipairs(test_cases) do
    print(string.format("Test %d: %s", i, test_case.name))
    
    -- Set up mock field values
    mock_field_values = {}
    for field_name, value in pairs(test_case.data) do
        mock_field_values[field_name] = value
    end
    
    -- Test the filtering logic
    local result = should_capture_event(test_case.data)
    
    if result == test_case.expected then
        print("  ✓ PASS")
        passed = passed + 1
    else
        print(string.format("  ✗ FAIL (expected %s, got %s)", tostring(test_case.expected), tostring(result)))
        failed = failed + 1
    end
    print()
end

-- Test MessagePack serialization
print("Testing MessagePack serialization...")
local test_data = {[1] = "test", [2] = 123, [3] = true}
local packed = messagepack.pack(test_data)
local unpacked = messagepack.unpack(packed)

local pack_test_passed = true
for k, v in pairs(test_data) do
    if unpacked[k] ~= v then
        pack_test_passed = false
        break
    end
end

if pack_test_passed then
    print("  ✓ MessagePack serialization PASS")
    passed = passed + 1
else
    print("  ✗ MessagePack serialization FAIL")
    failed = failed + 1
end
print()

-- Summary
print("========================================")
print(string.format("Tests completed: %d passed, %d failed", passed, failed))

if failed == 0 then
    print("All tests PASSED! ✓")
    os.exit(0)
else
    print("Some tests FAILED! ✗")
    os.exit(1)
end
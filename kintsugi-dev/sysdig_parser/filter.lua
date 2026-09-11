description = "Simplified sysdig event capture with MessagePack output"
short_description = "capture events as MessagePack"
category = "Custom"

args = {} 

local messagepack = require ("MessagePack")

-- Load fields from configuration file
local function load_fields_config(filename)
    local fields = {}
    local file = io.open(filename, "r")
    if not file then
        error("Cannot open fields config file: " .. filename)
    end
    
    for line in file:lines() do
        line = line:match("^%s*(.-)%s*$")  -- trim whitespace
        if line ~= "" and not line:match("^#") then  -- skip empty lines and comments
            table.insert(fields, line)
        end
    end
    file:close()
    
    if #fields == 0 then
        error("No fields found in config file: " .. filename)
    end
    
    return fields
end

-- Load allowed syscalls from YAML file
local function load_syscalls_yaml(filename)
    local syscalls = {}
    local file = io.open(filename, "r")
    if not file then
        error("Cannot open syscalls YAML file: " .. filename)
    end

    for line in file:lines() do
        line = line:match("^%s*(.-)%s*$")  -- trim whitespace
        -- Match lines like "  - execve" (YAML list items)
        local syscall = line:match("^%-%s+(.+)$")
        if syscall then
            syscalls[syscall] = true  -- Use hash table for O(1) lookup
        end
    end
    file:close()

    if next(syscalls) == nil then
        error("No syscalls found in YAML file: " .. filename)
    end

    return syscalls
end

local fields = load_fields_config("fields.config")
local allowed_syscalls = load_syscalls_yaml("../config/syscalls.yaml")

local field_handles = {}
local key_to_index = {}

function on_init()
    -- Initialize field handles and index mapping
    for i, field in ipairs(fields) do
        field_handles[i] = chisel.request_field(field)
        key_to_index[field] = i
    end
    
    -- Output field mapping
    io.write(messagepack.pack(fields))
    return true
end

-- Get field value safely
local function get_field_value(handle)
    local value = evt.field(handle)
    return value == nil and "null" or value
end

local function should_capture_event(event_data)
    local container_id = event_data["container.id"]
    local proc_name = event_data["proc.name"]
    local evt_type = event_data["evt.type"]

    -- Filter by container
    if container_id == "host" or container_id == "" or proc_name == "hypercorn" then
        return false
    end

    -- Filter by syscall type (only capture allowed syscalls)
    if evt_type and not allowed_syscalls[evt_type] then
        return false
    end

    return true
end

function on_event()
    -- Collect field data
    local event_data = {}
    for i, field_name in ipairs(fields) do
        local value = get_field_value(field_handles[i])
        if value ~= "null" then
            event_data[field_name] = value
        end
    end
    
    -- Check if event should be captured
    if should_capture_event(event_data) then
        -- Convert to indexed format
        local indexed_data = {}
        for key, value in pairs(event_data) do
            indexed_data[key_to_index[key]] = value
        end
        
        io.write(messagepack.pack(indexed_data))
    end
end

function on_capture_end()
    -- Cleanup if needed
end

-- Export functions for testing
if not chisel then
    -- Running in test mode, return module table
    return {
        load_fields_config = load_fields_config,
        load_syscalls_yaml = load_syscalls_yaml,
        get_field_value = get_field_value,
        should_capture_event = should_capture_event,
        fields = fields,
        allowed_syscalls = allowed_syscalls,
        field_handles = field_handles,
        key_to_index = key_to_index
    }
end
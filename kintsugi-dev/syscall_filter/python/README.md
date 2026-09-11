# Python Syscall Filter - eBPF-based Runtime Syscall Filtering

Python bindings for the eBPF syscall filtering system, enabling runtime control of which syscalls Python applications can execute.

## Overview

This module provides Python applications with the same syscall filtering capabilities as the PHP extension, using a shared eBPF backend. It allows fine-grained, per-thread syscall whitelisting to prevent command injection and other syscall-based attacks.

### Key Features

- **Whitelist-based filtering**: Only explicitly allowed syscalls can execute
- **Per-thread granularity**: Each thread can have independent filtering rules
- **Reversible**: Unlike seccomp, filters can be dynamically enabled/disabled
- **Zero overhead when disabled**: No performance impact outside filtered code
- **Shared eBPF infrastructure**: Uses the same eBPF program as PHP extension

### Architecture

```
┌─────────────────────────────┐
│   Python Application        │
│                             │
│  syscall_filter_begin()     │◄─── Your Code
│  syscall_filter_end()       │
└──────────────┬──────────────┘
               │ prctl(45, ...)
               ▼
┌─────────────────────────────┐
│    Kernel Space (eBPF)      │
│                             │
│  Intercept prctl(45)        │
│  Update BPF maps            │
│  Filter syscalls            │
└─────────────────────────────┘
```

**Key difference from seccomp**:
- seccomp: Process-level, permanent, blacklist
- eBPF: Thread-level, reversible, whitelist

## Installation

### Prerequisites

1. **Linux kernel >= 4.4** with eBPF support
2. **BCC tools** (BPF Compiler Collection):
   ```bash
   sudo apt install python3-bpfcc bpfcc-tools
   ```
3. **x86-64 architecture** (syscall numbers are architecture-specific)

### Deploy to Container

```bash
# Copy module to container
cd syscall_filter/python/source
./build.sh <container_name>

# Verify deployment
docker exec <container_name> python3 -c \
  "import sys; sys.path.insert(0, '/tmp/python_syscall_filter'); \
   import syscall_filter; print(syscall_filter.__version__)"
```

## Usage

### Basic API

```python
import sys
sys.path.insert(0, '/tmp/python_syscall_filter')
from syscall_filter import syscall_filter_begin, syscall_filter_end

# Define allowed syscalls (whitelist mode)
allowed_syscalls = ['read', 'write', 'open', 'openat', 'close', 'stat', 'fstat']

# Enable filtering
syscall_filter_begin(allowed_syscalls)

# Only whitelisted syscalls work here
with open('/etc/hostname') as f:
    data = f.read()  # OK (uses read/open/close)

# This would fail with EPERM:
# subprocess.run(['ls'])  # execve not in whitelist

# Disable filtering
syscall_filter_end(allowed_syscalls)

# Now all syscalls work again
```

### Context Manager (Recommended)

```python
from syscall_filter import SyscallFilter

with SyscallFilter(['read', 'write', 'open', 'openat', 'close']):
    # Filtered code here
    with open('/tmp/test', 'w') as f:
        f.write('data')

    # This would fail with EPERM:
    # subprocess.run(['ls'])

# Filter automatically disabled after exiting context
```

### Example: Block Command Execution

To prevent command injection attacks, create a whitelist that excludes `execve`, `vfork`, `fork`, `clone`:

```python
from syscall_filter import SyscallFilter

# Define safe syscalls (everything except command execution)
safe_syscalls = [
    'read', 'write', 'open', 'openat', 'close',
    'stat', 'fstat', 'lstat', 'access',
    'mmap', 'munmap', 'brk',
    'socket', 'connect', 'sendto', 'recvfrom',
    # ... add more as needed, but NO execve/vfork/fork/clone
]

with SyscallFilter(safe_syscalls):
    # Normal operations work
    with open('/etc/passwd') as f:
        data = f.read()  # OK

    # Command execution blocked
    subprocess.run(['ls'])  # Fails with OSError: [Errno 1] Operation not permitted
```

## Running Tests

### Prerequisites

**IMPORTANT**: Start the eBPF loader on the **host** in a separate terminal (requires root):

```bash
# Terminal 1: Start eBPF loader (keep running)
cd syscall_filter
sudo python3 ebpf_load.py

# Verify BPF maps created
ls /sys/fs/bpf/target_ids  # Should exist
```

### Automated Tests

**In a second terminal**, run the test script:

```bash
# Terminal 2: Run tests
cd syscall_filter/python/test
sudo ./test.sh
```

This will:
1. Check if eBPF loader is running (exits if not)
2. Build and start test container
3. Deploy Python module
4. Run 5 functionality tests
5. Monitor blocked syscalls
6. Clean up container (eBPF loader keeps running)

### Manual Tests

```bash
# Terminal 1: Start eBPF loader (if not already running)
cd syscall_filter
sudo python3 ebpf_load.py

# Terminal 2: Run manual tests
# Start container
cd syscall_filter/python/test/container
docker-compose up -d

# Deploy module
cd ../../source
./build.sh syscall-filter-python-test

# Run tests
docker exec syscall-filter-python-test python3 /tmp/test_basic.py
```

## Troubleshooting

### "prctl() returned non-zero"

**Cause**: eBPF loader not running

**Fix**:
```bash
sudo python3 syscall_filter/ebpf_load.py &
```

### "BPF maps not found"

**Cause**: eBPF loader failed to start or crashed

**Check**:
```bash
# Check if loader is running
ps aux | grep ebpf_load

# Check BPF maps
ls /sys/fs/bpf/

# Check kernel logs
dmesg | tail -50
```

### "Could not import syscall_table"

**Cause**: syscall_table.py not in correct location

**Fix**: Ensure `syscall_filter/syscall_table.py` exists and `build.sh` copied it to container

### Syscalls not being blocked

**Symptoms**: Commands execute even inside filtered context

**Debug**:
```bash
# Monitor trace_pipe for blocked syscalls
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep BLOCKED

# Check if thread is in target_ids map
sudo bpftool map dump name target_ids

# Verify prctl(45) is being intercepted
# (You should see events when begin/end are called)
```

### Container permissions

**Note**: Containers do **NOT** need privileged mode or special capabilities!

The container only needs to make normal syscalls. eBPF runs on the host and intercepts syscalls at the kernel level.

```yaml
# This is sufficient:
services:
  app:
    image: python:3.10
    # NO privileged: true needed
    # NO cap_add needed
```

## Comparison with seccomp

| Feature | seccomp | eBPF (this module) |
|---------|---------|-------------------|
| Scope | Process-wide | Per-thread |
| Reversibility | Permanent once set | Dynamic enable/disable |
| Rule type | Blacklist | Whitelist |
| Performance | Native kernel | ~1μs overhead/syscall |
| Observability | Limited | Full (trace_pipe) |
| Multi-language | Requires C library | Shared eBPF backend |

**Migration from seccomp**:

```python
# Old (seccomp - from temp/Python/CVE-2022-4223):
import ctypes
lib = ctypes.CDLL('/tmp/libsyscall_blocker.so')
lib.enable_syscall_filter()  # Permanent! Cannot disable
# ... code ...
# Filter remains active forever

# New (eBPF):
from syscall_filter import SyscallFilter

safe_syscalls = ['read', 'write', 'open', ...]  # Your whitelist
with SyscallFilter(safe_syscalls):
    # ... code ...
# Automatically disabled, can be re-enabled later
```

## API Reference

### Core Functions

#### `syscall_filter_begin(syscall_names)`

Enable syscall filtering with whitelist.

**Parameters**:
- `syscall_names` (list): List of allowed syscall names

**Returns**: `bool` - True if successful

**Raises**:
- `ValueError`: Unknown syscall name
- `RuntimeError`: libc not available

**Example**:
```python
syscall_filter_begin(['read', 'write', 'open'])
```

#### `syscall_filter_end(syscall_names)`

Disable syscall filtering.

**Parameters**:
- `syscall_names` (list): Same list as begin()

**Returns**: `bool` - True if successful

### Context Manager

#### `SyscallFilter(allowed_syscalls)`

Context manager for syscall filtering.

**Parameters**:
- `allowed_syscalls` (list): List of syscall names to whitelist

**Example**:
```python
with SyscallFilter(['read', 'write']):
    # Filtered code
    pass
```

### Constants

#### `PR_SYSCALL_FILTER_CMD`
Command number for prctl (45)

#### `CMD_BEGIN`
Begin filtering command (0)

#### `CMD_END`
End filtering command (1)

#### `SyscallCmd`
ctypes Structure matching the C structure used in PHP extension

## Real-world Example: CVE-2022-4223 Fix

pgAdmin command injection vulnerability (CVE-2022-4223):

```python
# In pgadmin/misc/__init__.py, function validate_binary_path():

import sys
sys.path.insert(0, '/tmp/python_syscall_filter')
from syscall_filter import SyscallFilter

def validate_binary_path(user_input):
    """Validate binary path from user input"""

    # Define safe syscalls (excludes execve/vfork/fork)
    safe_syscalls = [
        'read', 'write', 'open', 'openat', 'close',
        'stat', 'fstat', 'lstat', 'access',
        'mmap', 'munmap', 'brk',
        'getpid', 'gettid',
        # ... add other needed syscalls
    ]

    with SyscallFilter(safe_syscalls):
        # Original vulnerable code
        # If user_input contains command injection, execve will fail with EPERM
        result = validate_and_check(user_input)
        return result

    # Filter automatically disabled here
```

**Result**: Command injection attempts fail at syscall level, preventing RCE.

## Performance

- **Overhead when disabled**: 0% (no hooks active)
- **Overhead when enabled**: ~1-5% (eBPF kprobe overhead)
- **prctl(45) call**: ~1μs per begin/end
- **Syscall check**: ~0.1μs per filtered syscall

**Recommendation**: Enable filtering only around security-critical code, not entire application.

## Limitations

1. **Architecture**: x86-64 only (syscall numbers differ on ARM)
2. **Kernel version**: Requires Linux >= 4.4
3. **Root requirement**: eBPF loader must run as root on host
4. **Thread-local**: Each thread must call begin() independently
5. **Syscall limit**: Maximum 64 syscalls per whitelist (due to prctl buffer size)

## Finding Syscall Numbers

To find which syscalls your code needs:

```bash
# Method 1: Use strace
strace -c python3 your_script.py 2>&1 | grep -v "^%"

# Method 2: Monitor with eBPF while testing
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep BLOCKED
# Then add blocked syscalls to your whitelist
```

Common syscalls for Python applications:
- **File I/O**: `read`, `write`, `open`, `openat`, `close`, `stat`, `fstat`, `lstat`
- **Memory**: `mmap`, `munmap`, `brk`, `mprotect`
- **Network**: `socket`, `connect`, `sendto`, `recvfrom`, `bind`, `listen`
- **Process info**: `getpid`, `gettid`, `getuid`, `geteuid`
- **Always needed**: `prctl` (automatically added)

## Contributing

When adding new features:

1. Update `syscall_filter.py` for core functionality
2. Add tests to `test/test_basic.py`
3. Update this README
4. Ensure backwards compatibility with PHP extension protocol

## See Also

- PHP extension: `syscall_filter/php7/`
- eBPF code generator: `syscall_filter/ebpf_code_gen.py`
- eBPF loader: `syscall_filter/ebpf_load.py`
- Syscall table: `syscall_filter/syscall_table.py`
- PHP C extension protocol: `syscall_filter/php7/source/syscall_filter.h`

## License

Part of the LLM Vulnerability Repair Project.

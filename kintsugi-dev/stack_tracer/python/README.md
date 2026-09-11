# Python Stack Tracer

Python function-level call stack tracer for vulnerability analysis and debugging.

## Directory Structure

```
stack_tracer/python/
├── source/
│   ├── tracer.py              # Core tracer implementation
│   ├── __init__.py            # Module initialization
│   ├── inject_generic.py      # Generic injection script
│   ├── middleware.py          # Web framework middleware support
│   ├── test_tracer.py         # Test script
│   ├── generate_injector.py   # Injection script generation tool
│   └── build.sh               # Deployment script
├── test/                      # Test cases
└── README.md                  # This document
```

## Core Principles

Uses Python's built-in `sys.settrace()` mechanism to implement function call tracing:

- **Event Capture**: Listens for `call` and `return` events.
- **Information Extraction**: Retrieves filename, line number, function name, arguments, etc., from the frame object.
- **Path Filtering**: Only traces code within specified paths.
- **Data Output**: Writes to `/dev/null`, captured as system calls by sysdig.

## Main Differences from PHP Version

| Feature | Python | PHP |
|------|--------|-----|
| Implementation | `sys.settrace()` | Zend Opcode Hook |
| Compilation | No compilation required | Requires C extension compilation |
| Output Format | `[FCALL]` / `[RETURN]` | `[FCALL]` / `[RETURN]` |
| Thread Support | Requires patching `threading.Thread` | No extra handling needed |
| Deployment | Copy .py files | Compile .so extension |

## Usage

### 1. Deploy Tracer to Container

```bash
# Arguments: <CVE_env_dir> <container_name>
bash build.sh cves/CVE-2022-4223/env cve-web-1
```

This will:
- Create `/tmp/python_tracer/` directory inside the container.
- Copy tracer files to the container.
- Create a placeholder `tracer.so` (for compatibility with main.sh).

### 2. Generate Injection Script

```bash
python3 generate_injector.py \
    --target-path /usr/local/lib/python3.10/site-packages/pgadmin4 \
    --app-entry /usr/local/bin/pgadmin4 \
    --output /tmp/inject_pgadmin.py
```

Argument Description:
- `--target-path`: The Python package path to trace.
- `--app-entry`: The application entry file.
- `--output`: Path for the generated injection script.

### 3. Inject into Application

```bash
# Copy injection script to container
docker cp /tmp/inject_pgadmin.py cve-web-1:/tmp/python_tracer/inject.py

# Modify app entry to insert injection code at the first line
docker exec cve-web-1 bash -c "
    sed -i '1a exec(open(\"/tmp/python_tracer/inject.py\").read())' /usr/local/bin/pgadmin4
"

# Restart application
docker restart cve-web-1
```

### 4. Verify Tracer

```bash
# Check tracer logs (if using file output)
docker exec cve-web-1 tail /tmp/app_tracer.log

# Or check sysdig capture
sudo sysdig -r capture.scap proc.name=python | grep "\[CALL\]"
```

## Output Format

### FCALL Event (Function Call)

```
[FCALL][/app/module.py:42][U]module.Class.function(arg1='value', arg2=123)
```

### RETURN Event (Function Return)

```
[RETURN][/app/module.py:42][U]module.Class.function[DEF:/app/module.py:10-?]
```

**Field Description**:
1. `[FCALL]` / `[RETURN]`: Event type.
2. `[/app/module.py:42]`: Call site (file:line).
3. `[U]`: User function marker (I for internal/built-in).
4. `module.Class.function`: Full function name.
5. `(arg1='value', arg2=123)`: Arguments (FCALL only).
6. `[DEF:/app/module.py:10-?]`: Function definition location (RETURN only).

## Thread Support

Python's `sys.settrace()` is thread-local; each new thread must set it individually.

The injection script automatically patches `threading.Thread.__init__` to ensure all new threads enable tracing:

```python
original_thread_init = threading.Thread.__init__

def patched_thread_init(self, *args, **kwargs):
    original_thread_init(self, *args, **kwargs)
    original_run = self.run

    def run_with_trace(*args, **kwargs):
        sys.settrace(_tracer)
        try:
            original_run(*args, **kwargs)
        finally:
            sys.settrace(None)

    self.run = run_with_trace

threading.Thread.__init__ = patched_thread_init
```

## Configuration Options

Configurable in `tracer.py`:

```python
enable_tracer(
    target_paths=['/app'],      # List of paths to trace
    capture_args=True,          # Whether to capture function arguments
    max_depth=100,              # Maximum trace depth
    output_file=None            # Output file (None = /dev/null)
)
```

## Integration into main.sh

Add Python support in `main.sh`:

```bash
# CVE configuration
language=python
version=3.10
cve=CVE-2022-4223
container=cve-web-1
python_target_path=/usr/local/lib/python3.10/site-packages/pgadmin4
python_app_entry=/usr/local/bin/pgadmin4

# Deploy tracer
if [ "$language" = "python" ]; then
    bash stack_tracer/python/source/build.sh cves/${cve}/env ${container}

    # Generate injection script
    python3 stack_tracer/python/source/generate_injector.py \
        --target-path "${python_target_path}" \
        --app-entry "${python_app_entry}" \
        --output /tmp/inject_${cve}.py

    # Copy and inject
    docker cp /tmp/inject_${cve}.py ${container}:/tmp/python_tracer/inject.py
    docker exec $container sed -i '1a exec(open("/tmp/python_tracer/inject.py").read())' ${python_app_entry}

    # Restart container
    docker restart $container
fi
```

## Troubleshooting

### Tracer Not Working

1. Check if the injection script is executed:
   ```bash
   docker exec cve-web-1 grep "inject.py" /usr/local/bin/pgadmin4
   ```

2. Check error logs:
   ```bash
   docker logs cve-web-1 2>&1 | grep Tracer
   ```

### Empty Output

1. Confirm path filtering is correct:
   ```python
   # Check if target_paths includes the application code path
   enable_tracer(target_paths=['/usr/local/lib/python3.10/site-packages/pgadmin4'])
   ```

2. Confirm sysdig is capturing:
   ```bash
   sudo sysdig -p "%evt.type %proc.name" | grep write
   ```

### Performance Issues

The tracer adds 20-50% performance overhead. Optimize by:

1. Limiting trace depth: `max_depth=50`
2. Disabling argument capture: `capture_args=False`
3. Specifying precise `target_paths` to avoid tracing third-party libraries.

## Development and Testing

Run tests:
```bash
python3 test_tracer.py
```

Manual test:
```bash
python3 -c "
import sys
sys.path.insert(0, '.')
from tracer import enable_tracer

enable_tracer(target_paths=['/tmp'], output_file='/tmp/test.log')

def test_func(x):
    return x * 2

test_func(21)
"

cat /tmp/test.log
```

## References

- Python Official Docs: [`sys.settrace()`](https://docs.python.org/3/library/sys.html#sys.settrace)
- PHP tracer implementation: `stack_tracer/php7/source/tracer.c`
- CVE Example: `cves/CVE-2022-4223/`

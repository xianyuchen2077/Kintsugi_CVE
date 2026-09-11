# PHP8.x Tracer Extension

## Overview

This script automates the compilation of the PHP Tracer extension, resolving PHP version compatibility issues by building inside a Docker container.

## File Structure

```
php8/
├── source/
│   ├── 99-tracer.ini      # PHP INI configuration
│   ├── build.sh           # Build script
│   ├── config.m4          # Autoconf configuration
│   ├── php_tracer.h       # Header file
│   ├── tracer.c           # Extension source
│   └── README.md          # This document
└── test/
    ├── container/         # Docker container config
    ├── web/               # Test PHP scripts
    └── test.sh            # Test runner
```

## Prerequisites

- Docker and Docker Compose installed

## Usage

```bash
./build.sh <cve_env_dir> <container_name>
```

## Build Process

The script performs the following steps:

1. **Environment Check** - Verify Docker is running and required files exist
2. **Container Management** - Stop existing container (if running), start the PHP8 build container
3. **Source Preparation** - Copy source files to `/tmp/tracer-build` inside the container
4. **Compilation**
   ```bash
   phpize
   ./configure --enable-tracer
   make clean
   make
   ```
5. **Output Handling** - Verify `modules/tracer.so`, copy to host, clean up, stop container

## Result

After a successful build, the following file is generated:
- `tracer.so` - PHP extension shared library

### Trace Output

The tracer writes function call traces to `/dev/null`, which can be captured using `sysdig`:
```bash
sysdig -s 8192 -v -p "%evt.time %proc.name %evt.buffer" \
    "evt.type=write and fd.name=/dev/null" > trace.log
```

### Output Format
```
[TYPE][CALL_LOCATION][SCOPE]FUNCTION_NAME[DEF:DEFINITION_LOCATION](ARGUMENTS).
[RETURN][CALL_LOCATION][SCOPE]FUNCTION_NAME[DEF:DEFINITION_LOCATION].
```

- `TYPE`: `FCALL`, `UCALL`, `ICALL`, `FCALL_BY_NAME`, `RETURN`
- `SCOPE`: `U` (user-defined), `I` (internal/built-in)

### Example
```
[FCALL][/var/www/html/test.php:57][U]MyClass::__construct[DEF:/var/www/html/test.php:5-7]().
[ICALL][/var/www/html/test.php:61][I]implode(", ", Array(5)).
[RETURN][/var/www/html/test.php:11][U]MyClass::doSomething[DEF:/var/www/html/test.php:9-11].
```

#!/bin/bash

# Build script for compiling the tracer PHP extension inside a Docker container.
# Usage: $0 <cve_env_dir> <container_name>

set -e

CVE_ENV_DIR="$1"
CONTAINER_NAME="$2"

if [ -z "$CVE_ENV_DIR" ] || [ -z "$CONTAINER_NAME" ]; then
    echo "Usage: $0 <cve_env_dir> <container_name>"
    echo "Example: $0 cves/CVE-2015-8562/env env-web-1"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script requires root privileges."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR"
CVE_ENV_DIR="$(cd "$CVE_ENV_DIR" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

check_docker() {
    log "Checking Docker status..."
    if ! docker info >/dev/null 2>&1; then
        error "Docker is not running or inaccessible. Please ensure Docker Desktop is started."
    fi
    success "Docker is running."
}

start_container() {
    log "Starting container: $CONTAINER_NAME"
    cd "$CVE_ENV_DIR"
    rm -rf "$CVE_ENV_DIR/tracer.so"
    touch "$CVE_ENV_DIR/tracer.so"

    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log "Container exists, starting..."
        docker start "$CONTAINER_NAME"
    else
        log "Container does not exist, creating..."
        docker compose up -d
    fi

    log "Waiting for container to be ready..."
    sleep 5

    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        success "Container started."
    else
        error "Failed to start container."
    fi
}

stop_container() {
    log "Stopping container: $CONTAINER_NAME"

    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        docker stop "$CONTAINER_NAME"
        success "Container stopped."
    else
        log "Container is not running, skipping."
    fi
}

copy_source_to_container() {
    log "Copying source to container: $CONTAINER_NAME"

    docker exec "$CONTAINER_NAME" mkdir -p /tmp/tracer-build
    docker cp "$SOURCE_DIR/." "$CONTAINER_NAME:/tmp/tracer-build/"

    success "Source copied to container:/tmp/tracer-build/"
}

compile_in_container() {
    log "Compiling in container: $CONTAINER_NAME"

    COMPILE_SCRIPT='
set -e
cd /tmp/tracer-build

echo "=== 1. Running phpize ==="
phpize
ls -la

echo "=== 2. Configuring ==="
./configure --enable-tracer

echo "=== 3. Building ==="
make clean
make

echo "=== 4. Verifying build output ==="
ls -la modules/
if [ -f "modules/tracer.so" ]; then
    echo "SUCCESS: tracer.so compiled successfully!"
    file modules/tracer.so
else
    echo "ERROR: tracer.so not found!"
    exit 1
fi
'

    if docker exec "$CONTAINER_NAME" bash -c "$COMPILE_SCRIPT"; then
        success "Compilation complete."
    else
        error "Compilation failed."
    fi
}

copy_result_to_cve_env() {
    log "Copying build output to CVE environment..."

    if docker cp "$CONTAINER_NAME:/tmp/tracer-build/modules/tracer.so" "$CVE_ENV_DIR/tracer.so"; then
        success "tracer.so copied to $CVE_ENV_DIR/"
    else
        error "Failed to copy tracer.so from $CONTAINER_NAME:/tmp/tracer-build/modules/tracer.so to $CVE_ENV_DIR. Current directory: $(pwd)"
    fi

    if [ -f "$CVE_ENV_DIR/tracer.so" ]; then
        log "Verifying build output:"
        ls -la "$CVE_ENV_DIR/tracer.so"
        file "$CVE_ENV_DIR/tracer.so"
        success "Build complete! tracer.so is ready."
    else
        error "tracer.so not found."
    fi
}

cleanup() {
    log "Cleaning up temporary files..."
    docker exec "$CONTAINER_NAME" rm -rf /tmp/tracer-build || true
    success "Temporary files cleaned up."
}

main() {
    echo "======================================================"
    echo "    PHP Tracer Extension Build Script"
    echo "======================================================"
    echo "CVE env directory: $CVE_ENV_DIR"
    echo "Container name:    $CONTAINER_NAME"
    echo "======================================================"

    if [ ! -d "$CVE_ENV_DIR" ]; then
        error "CVE environment directory not found: $CVE_ENV_DIR"
    fi

    if [ ! -f "$SOURCE_DIR/tracer.c" ]; then
        error "Source file not found: $SOURCE_DIR/tracer.c"
    fi

    if [ ! -f "$CVE_ENV_DIR/docker-compose.yml" ]; then
        error "docker-compose.yml not found: $CVE_ENV_DIR/docker-compose.yml"
    fi

    check_docker
    start_container
    copy_source_to_container
    compile_in_container
    copy_result_to_cve_env
    cleanup
    stop_container

    echo "======================================================"
    success "Build process complete!"
    echo "Output: $CVE_ENV_DIR/tracer.so"
    echo "======================================================"
}

trap 'error "Script failed. Check the output above for details."' ERR

main "$@"

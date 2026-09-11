#!/bin/bash
# build.sh - Deploy Python syscall_filter module to container
#
# Usage: ./build.sh <container_name>
#
# This script copies the Python syscall_filter module to a container so that
# Python applications inside the container can use syscall filtering.
#
# Requirements:
#   - Container must be running
#   - eBPF loader must be running on host (sudo python3 ebpf_load.py)

set -e

SCRIPT_DIR=$(dirname "$(realpath "$0")")
CONTAINER_NAME=${1:-""}

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ============================================================================
# Helper functions
# ============================================================================

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

# ============================================================================
# Main deployment
# ============================================================================

echo "==========================================================================="
echo " Python Syscall Filter - Deployment Script"
echo "==========================================================================="
echo

# Check arguments
if [ -z "$CONTAINER_NAME" ]; then
    print_error "Container name not specified"
    echo "Usage: $0 <container_name>"
    echo
    echo "Example:"
    echo "  $0 python-test-1"
    echo "  $0 cve-web-1"
    exit 1
fi

# Check if container exists and is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    print_error "Container '$CONTAINER_NAME' is not running"
    echo
    echo "Available running containers:"
    docker ps --format "  - {{.Names}}"
    exit 1
fi

print_info "Deploying to container: $CONTAINER_NAME"
echo

# Step 1: Create target directory in container
print_info "Step 1/4: Creating target directory..."
if docker exec "$CONTAINER_NAME" mkdir -p /tmp/python_syscall_filter; then
    print_success "Directory created: /tmp/python_syscall_filter"
else
    print_error "Failed to create directory"
    exit 1
fi

# Step 2: Copy Python module files
print_info "Step 2/4: Copying Python module files..."

FILES=(
    "__init__.py"
    "syscall_filter.py"
)

for file in "${FILES[@]}"; do
    if [ ! -f "$SCRIPT_DIR/$file" ]; then
        print_error "File not found: $file"
        exit 1
    fi

    if docker cp "$SCRIPT_DIR/$file" "$CONTAINER_NAME:/tmp/python_syscall_filter/"; then
        print_success "Copied: $file"
    else
        print_error "Failed to copy: $file"
        exit 1
    fi
done

# Step 3: Copy syscall_table.py
print_info "Step 3/4: Copying syscall_table.py..."

SYSCALL_TABLE="$SCRIPT_DIR/../../syscall_table.py"
if [ ! -f "$SYSCALL_TABLE" ]; then
    print_error "syscall_table.py not found at: $SYSCALL_TABLE"
    exit 1
fi

if docker cp "$SYSCALL_TABLE" "$CONTAINER_NAME:/tmp/python_syscall_filter/"; then
    print_success "Copied: syscall_table.py"
else
    print_error "Failed to copy syscall_table.py"
    exit 1
fi

# Step 4: Verify deployment
print_info "Step 4/4: Verifying deployment..."

VERIFY_CMD="python3 -c 'import sys; sys.path.insert(0, \"/tmp/python_syscall_filter\"); import syscall_filter; print(\"Version:\", syscall_filter.__version__)'"

if docker exec "$CONTAINER_NAME" sh -c "$VERIFY_CMD" 2>/dev/null; then
    print_success "Module can be imported successfully"
else
    print_error "Module import failed"
    echo
    echo "Try testing manually:"
    echo "  docker exec $CONTAINER_NAME python3 -c 'import sys; sys.path.insert(0, \"/tmp/python_syscall_filter\"); import syscall_filter; print(syscall_filter.__version__)'"
    exit 1
fi

echo
echo "==========================================================================="
print_success "Deployment complete!"
echo "==========================================================================="
echo
echo "Module location: /tmp/python_syscall_filter"
echo
echo "Usage in Python:"
echo "  import sys"
echo "  sys.path.insert(0, '/tmp/python_syscall_filter')"
echo "  from syscall_filter import syscall_filter_begin, syscall_filter_end"
echo
echo "IMPORTANT: Ensure eBPF loader is running on host:"
echo "  sudo python3 syscall_filter/ebpf_load.py &"
echo

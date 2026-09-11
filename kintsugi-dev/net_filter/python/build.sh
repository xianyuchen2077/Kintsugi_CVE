#!/bin/bash
# build.sh - Deploy Python net_filter module to container
#
# Usage: ./build.sh <container_name>
#
# Copies net_filter module to /tmp/python_net_filter in the container
# Usage in Python:
#   import sys
#   sys.path.insert(0, '/tmp/python_net_filter')
#   from net_filter import NetFilter

set -e

SCRIPT_DIR=$(dirname "$(realpath "$0")")
CONTAINER_NAME=${1:-""}

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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
# Main
# ============================================================================

echo "==========================================================================="
echo " Python net_filter - Deployment Script"
echo "==========================================================================="
echo

# Check arguments
if [ -z "$CONTAINER_NAME" ]; then
    print_error "No container name specified"
    echo "Usage: $0 <container_name>"
    echo
    echo "Example:"
    echo "  $0 net-filter-python-test"
    echo "  $0 cve-web-1"
    exit 1
fi

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    print_error "Container '$CONTAINER_NAME' is not running"
    echo
    echo "Available containers:"
    docker ps --format "  - {{.Names}}"
    exit 1
fi

print_info "Target container: $CONTAINER_NAME"
echo

# Step 1: Create directory
print_info "Step 1/3: Creating directory..."
if docker exec "$CONTAINER_NAME" mkdir -p /tmp/python_net_filter; then
    print_success "Directory created: /tmp/python_net_filter"
else
    print_error "Failed to create directory"
    exit 1
fi

# Step 2: Copy files
print_info "Step 2/3: Copying module files..."

# Check source file
if [ ! -f "$SCRIPT_DIR/net_filter.py" ]; then
    print_error "net_filter.py not found"
    exit 1
fi

# Copy net_filter.py
if docker cp "$SCRIPT_DIR/net_filter.py" "$CONTAINER_NAME:/tmp/python_net_filter/"; then
    print_success "Copied: net_filter.py"
else
    print_error "Copy failed: net_filter.py"
    exit 1
fi

# Create __init__.py
if docker exec "$CONTAINER_NAME" sh -c "echo 'from .net_filter import NetFilter, __version__' > /tmp/python_net_filter/__init__.py"; then
    print_success "Created: __init__.py"
else
    print_error "Failed to create: __init__.py"
    exit 1
fi

# Step 3: Verify
print_info "Step 3/3: Verifying deployment..."

VERIFY_CMD="python3 -c 'import sys; sys.path.insert(0, \"/tmp/python_net_filter\"); from net_filter import NetFilter, __version__; print(\"version:\", __version__)'"

if docker exec "$CONTAINER_NAME" sh -c "$VERIFY_CMD" 2>/dev/null; then
    print_success "Module imported successfully"
else
    print_error "Module import failed"
    echo
    echo "Manual test:"
    echo "  docker exec $CONTAINER_NAME python3 -c 'import sys; sys.path.insert(0, \"/tmp/python_net_filter\"); from net_filter import NetFilter; print(\"OK\")'"
    exit 1
fi

echo
echo "==========================================================================="
print_success "Deployment complete!"
echo "==========================================================================="
echo
echo "Module path: /tmp/python_net_filter"
echo
echo "Usage:"
echo "  import sys"
echo "  sys.path.insert(0, '/tmp/python_net_filter')"
echo "  from net_filter import NetFilter"
echo
echo "  with NetFilter(external_only=True):"
echo "      # Internal network is blocked"
echo "      response = requests.get(url)"
echo
echo "Note: Ensure host setup has been run:"
echo "  sudo ../setup.sh $CONTAINER_NAME"
echo

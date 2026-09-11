#!/bin/bash
# build.sh - Deploy PHP net_filter Module to Container
#
# Usage: ./build.sh <container-name>
#
# Copy net_filter module to /tmp/php_net_filter directory of the target container
# Usage in PHP:
#   require_once '/tmp/php_net_filter/net_filter.php';

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
echo " PHP net_filter - Deployment Script"
echo "==========================================================================="
echo

# Check input parameter
if [ -z "$CONTAINER_NAME" ]; then
    print_error "Container name not specified"
    echo "Usage: $0 <container-name>"
    echo
    echo "Examples:"
    echo "  $0 net-filter-php-test"
    echo "  $0 cve-web-1"
    exit 1
fi

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    print_error "Container '$CONTAINER_NAME' is not running"
    echo
    echo "Available running containers:"
    docker ps --format "  - {{.Names}}"
    exit 1
fi

print_info "Target Container: $CONTAINER_NAME"
echo

# Step 1: Create target directory
print_info "Step 1/3: Creating target directory..."
if docker exec "$CONTAINER_NAME" mkdir -p /tmp/php_net_filter; then
    print_success "Directory created: /tmp/php_net_filter"
else
    print_error "Failed to create directory"
    exit 1
fi

# Step 2: Copy module files
print_info "Step 2/3: Copying module files..."

# Check source file existence
if [ ! -f "$SCRIPT_DIR/net_filter.php" ]; then
    print_error "net_filter.php not found in script directory"
    exit 1
fi

# Copy net_filter.php to container
if docker cp "$SCRIPT_DIR/net_filter.php" "$CONTAINER_NAME:/tmp/php_net_filter/"; then
    print_success "Copied: net_filter.php"
else
    print_error "Failed to copy: net_filter.php"
    exit 1
fi

# Step 3: Verify deployment
print_info "Step 3/3: Verifying deployment..."

VERIFY_CMD="php -r 'require_once \"/tmp/php_net_filter/net_filter.php\"; echo \"OK\n\";'"

if docker exec "$CONTAINER_NAME" bash -c "$VERIFY_CMD" 2>/dev/null; then
    print_success "Module loaded successfully"
else
    print_error "Module load failed"
    echo
    echo "Manual verification command:"
    echo "  docker exec $CONTAINER_NAME php -r 'require_once \"/tmp/php_net_filter/net_filter.php\"; echo \"OK\n\";'"
    exit 1
fi

echo
echo "==========================================================================="
print_success "Deployment completed successfully!"
echo "==========================================================================="
echo
echo "Module Path: /tmp/php_net_filter/net_filter.php"
echo
echo "Basic Usage:"
echo "  require_once '/tmp/php_net_filter/net_filter.php';"
echo
echo "  net_filter_begin(true);  // Enable external_only mode (block internal network)"
echo "  \$response = file_get_contents(\$url);  // Internal network access blocked"
echo "  net_filter_end();        // Disable filter, restore normal network"
echo
echo "Class-based Usage:"
echo "  \$filter = new NetFilter(true);  // external_only=true"
echo "  \$filter->begin();"
echo "  // ... Network operations here ..."
echo "  \$filter->end();"
echo
echo "Note: Ensure host machine setup script has been executed:"
echo "  sudo ../setup.sh $CONTAINER_NAME"
echo
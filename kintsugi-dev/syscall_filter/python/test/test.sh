#!/bin/bash
# test.sh - Automated testing for Python syscall_filter
#
# This script:
# 1. Starts test container
# 2. Deploys Python syscall_filter module
# 2.5. Tests auto-installation functionality
# 3. Copies test script to container
# 4. Checks eBPF loader status
# 5. Starts trace_pipe monitoring
# 6. Runs functionality tests
# 7. Displays blocked syscalls
# 8. Cleans up

set -e

SCRIPT_DIR=$(dirname "$(realpath "$0")")
CONTAINER_DIR="$SCRIPT_DIR/container"
SOURCE_DIR="$SCRIPT_DIR/../source"
SYSCALL_FILTER_ROOT="$SCRIPT_DIR/../.."

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

print_step() {
    echo -e "\n${BLUE}[$1]${NC} $2"
}

cleanup() {
    print_info "Cleaning up..."

    # Stop trace_pipe monitoring
    if [ -n "$TRACE_PID" ]; then
        sudo kill $TRACE_PID 2>/dev/null || true
    fi

    # Note: We do NOT stop eBPF loader (it was started manually by user)

    # Stop container
    if [ "$KEEP_CONTAINER" != "1" ]; then
        print_info "Stopping container..."
        cd "$CONTAINER_DIR"
        docker-compose down 2>/dev/null || true
    else
        print_info "Keeping container running (KEEP_CONTAINER=1)"
    fi
}

# Trap exit signals
trap cleanup EXIT INT TERM

# ============================================================================
# Main test workflow
# ============================================================================

echo "==========================================================================="
echo " Python Syscall Filter - Automated Testing"
echo "==========================================================================="
echo

# Check if running as root (needed for eBPF)
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root (needed for eBPF loader)"
    echo "Please run: sudo $0"
    exit 1
fi

# Parse arguments
KEEP_CONTAINER=${KEEP_CONTAINER:-0}
VERBOSE=${VERBOSE:-0}

# Step 1: Start test container
print_step "1/7" "Starting test container"
cd "$CONTAINER_DIR"

CONTAINER_NAME="syscall-filter-python-test"

if docker ps | grep -q "$CONTAINER_NAME"; then
    print_info "Container already running"
else
    print_info "Starting container..."
    docker-compose up -d
    sleep 5
fi

print_success "Container running: $CONTAINER_NAME"

# Step 2: Deploy Python module
print_step "2/7" "Deploying Python syscall_filter module"
bash "$SOURCE_DIR/build.sh" "$CONTAINER_NAME"

if [ $? -ne 0 ]; then
    print_error "Module deployment failed"
    exit 1
fi

# Step 3: Copy test scripts to container
print_step "3/8" "Copying test scripts to container"
docker cp "$SCRIPT_DIR/test_basic.py" "$CONTAINER_NAME:/tmp/"
docker cp "$SCRIPT_DIR/test_path_filtering.py" "$CONTAINER_NAME:/tmp/"
docker cp "$SCRIPT_DIR/test_cascading.py" "$CONTAINER_NAME:/tmp/"
print_success "Test scripts copied"

# Step 4: Check eBPF loader status
print_step "4/8" "Checking eBPF loader status"
cd "$SYSCALL_FILTER_ROOT"

# Check if BPF maps exist (meaning eBPF loader is running)
if [ -e "/sys/fs/bpf/target_ids" ]; then
    print_success "eBPF loader is already running (BPF maps found)"
    EBPF_PID=""
else
    print_error "eBPF loader is not running"
    echo ""
    echo "Please start eBPF loader manually in another terminal:"
    echo "  cd $SYSCALL_FILTER_ROOT"
    echo "  sudo python3 ebpf_load.py"
    echo ""
    echo "Then run this test script again."
    exit 1
fi

# Step 5: Start trace_pipe monitoring (optional)
print_step "5/8" "Starting trace_pipe monitoring"
if [ -r "/sys/kernel/debug/tracing/trace_pipe" ]; then
    print_info "Monitoring blocked syscalls in background..."
    sudo cat /sys/kernel/debug/tracing/trace_pipe | grep --line-buffered "BLOCKED" > /tmp/blocked_syscalls.log 2>&1 &
    TRACE_PID=$!
    echo "  trace_pipe PID: $TRACE_PID"
else
    print_info "trace_pipe not accessible, skipping monitoring"
    TRACE_PID=""
fi

# Step 6: Run tests
print_step "6/8" "Running functionality tests"
echo

# Run basic tests
print_info "Running test_basic.py..."
if docker exec -it "$CONTAINER_NAME" python3 /tmp/test_basic.py; then
    print_success "test_basic.py passed"
    TEST_RESULT=0
else
    TEST_RESULT=$?
    print_error "test_basic.py failed with exit code $TEST_RESULT"
fi

# Run path filtering tests
echo
print_info "Running test_path_filtering.py..."
if docker exec -it "$CONTAINER_NAME" python3 /tmp/test_path_filtering.py; then
    print_success "test_path_filtering.py passed"
else
    PATH_TEST_RESULT=$?
    print_error "test_path_filtering.py failed with exit code $PATH_TEST_RESULT"
    TEST_RESULT=$PATH_TEST_RESULT
fi

# Run cascading monitoring tests
echo
print_info "Running test_cascading.py..."
if docker exec -it "$CONTAINER_NAME" python3 /tmp/test_cascading.py; then
    print_success "test_cascading.py passed"
else
    CASCADING_TEST_RESULT=$?
    print_error "test_cascading.py failed with exit code $CASCADING_TEST_RESULT"
    TEST_RESULT=$CASCADING_TEST_RESULT
fi

# Step 7: Display blocked syscalls (if any)
print_step "7/8" "Checking for blocked syscalls"
sleep 1

if [ -f "/tmp/blocked_syscalls.log" ] && [ -s "/tmp/blocked_syscalls.log" ]; then
    print_success "Blocked syscalls detected (this is expected):"
    echo
    head -20 /tmp/blocked_syscalls.log | sed 's/^/  /'
    echo
    LINE_COUNT=$(wc -l < /tmp/blocked_syscalls.log)
    if [ $LINE_COUNT -gt 20 ]; then
        echo "  ... and $((LINE_COUNT - 20)) more lines"
    fi
else
    print_info "No blocked syscalls logged"
    if [ -n "$TRACE_PID" ]; then
        echo "  (trace_pipe monitoring was active, but no BLOCKED events captured)"
    fi
fi

echo
echo "==========================================================================="
if [ $TEST_RESULT -eq 0 ]; then
    print_success "All tests passed!"
else
    print_error "Some tests failed"
fi
echo "==========================================================================="
echo

# Display useful info
echo "Logs:"
echo "  Blocked syscalls: /tmp/blocked_syscalls.log"
echo

if [ "$KEEP_CONTAINER" = "1" ]; then
    echo "Container kept running. To test manually:"
    echo "  docker exec -it $CONTAINER_NAME python3 /tmp/test_basic.py"
    echo "  docker exec -it $CONTAINER_NAME python3 /tmp/test_path_filtering.py"
    echo "  docker exec -it $CONTAINER_NAME python3 /tmp/test_cascading.py"
    echo
    echo "To stop container:"
    echo "  docker stop $CONTAINER_NAME"
    echo
    echo "Note: eBPF loader is running independently (not managed by this script)"
fi

exit $TEST_RESULT

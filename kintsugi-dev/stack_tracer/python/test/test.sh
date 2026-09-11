#!/bin/bash

# Python Tracer Automated Test Script
# Automates deployment and testing, using sysdig to monitor system calls

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_CONTAINER_DIR="$SCRIPT_DIR/container"
TEST_CONTAINER_NAME="stack-tracer-python-test"
BUILD_SCRIPT="$SOURCE_ROOT/source/build.sh"
LOG_DIR="$SCRIPT_DIR/log"

echo "======================================================"
echo "    Python Tracer Automated Test Script"
echo "======================================================"

# Check environment
if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker is not running"
    exit 1
fi

if ! command -v sysdig >/dev/null 2>&1; then
    echo "WARNING: sysdig is not installed, skipping syscall monitoring"
    SKIP_SYSDIG=true
else
    SKIP_SYSDIG=false
fi

# Check sudo privileges (sysdig requires root)
if [ "$SKIP_SYSDIG" = false ] && [ "$EUID" -ne 0 ]; then
    echo "ERROR: sysdig monitoring requires sudo privileges"
    echo "Please use: sudo bash test.sh"
    exit 1
fi

if [ ! -d "$TEST_CONTAINER_DIR" ]; then
    echo "ERROR: Test container directory does not exist: $TEST_CONTAINER_DIR"
    exit 1
fi

# Create log directory
mkdir -p "$LOG_DIR"

# Step 1: Start test container
echo ""
echo "=== Step 1: Start test container ==="
cd "$TEST_CONTAINER_DIR"
docker compose down >/dev/null 2>&1 || true
docker compose up -d
sleep 5

# Debug: Show all container statuses
echo "All containers:"
docker ps -a --format "{{.Names}} {{.Status}}" | grep -i stack || true

CONTAINER_ID=$(docker ps --filter "name=$TEST_CONTAINER_NAME" --format "{{.ID}}")
if [ -z "$CONTAINER_ID" ]; then
    echo "ERROR: Could not get container ID"
    echo "Attempting to view container logs:"
    docker logs "$TEST_CONTAINER_NAME" 2>&1 | tail -20 || true
    exit 1
fi

echo "Container ID: $CONTAINER_ID"

# Step 2: Deploy tracer
echo ""
echo "=== Step 2: Deploy Python Tracer ==="
bash "$BUILD_SCRIPT" "$TEST_CONTAINER_NAME"

# Step 3: Deploy test files
echo ""
echo "=== Step 3: Deploy test files ==="
docker exec "$CONTAINER_ID" mkdir -p /app/tests
docker cp "$SCRIPT_DIR/web/." "$CONTAINER_ID:/app/tests/"
echo "Test files deployed"

# Step 4: Execute tests (tracer auto-loaded via sitecustomize)
echo ""
echo "=== Step 4: Execute tests (sysdig monitoring) ==="

for test_file in "$SCRIPT_DIR/web/"*.py; do
    if [ -f "$test_file" ]; then
        filename=$(basename "$test_file")
        test_name="${filename%.py}"

        echo ""
        echo "Executing test: $filename"
        echo "================================"

        SYSDIG_LOG="$LOG_DIR/${test_name}.log"
        PYTHON_OUTPUT="$LOG_DIR/${test_name}_output.txt"

        # Start sysdig monitoring (if available)
        if [ "$SKIP_SYSDIG" = false ]; then
            echo "  Starting sysdig monitoring..."
            sysdig -s 8192 -v -p "%evt.buffer" \
                "evt.type=write and proc.name=python3 and fd.num=3" \
                > "$SYSDIG_LOG" 2>&1 &
            SYSDIG_PID=$!

            sleep 5  # Wait for monitoring to start
        fi

        # Execute Python test
        echo "  Executing command: docker exec $CONTAINER_ID python3 /app/tests/$filename"
        if docker exec "$CONTAINER_ID" python3 /app/tests/$filename > "$PYTHON_OUTPUT" 2>&1; then
            echo "  ✓ Python execution successful"
            cat "$PYTHON_OUTPUT" | sed 's/^/    /'
        else
            echo "  ✗ Python execution failed"
            cat "$PYTHON_OUTPUT" | sed 's/^/    /'
        fi

        # Stop sysdig monitoring
        if [ "$SKIP_SYSDIG" = false ]; then
            sleep 5  # Wait for syscalls to complete
            echo "  Stopping sysdig monitoring..."
            kill $SYSDIG_PID 2>/dev/null || true
            wait $SYSDIG_PID 2>/dev/null || true

            # Show statistics
            FCALL_COUNT=$(grep -c "\[FCALL\]" "$SYSDIG_LOG" 2>/dev/null || echo "0")
            RETURN_COUNT=$(grep -c "\[RETURN\]" "$SYSDIG_LOG" 2>/dev/null || echo "0")
            echo "  Captured: $FCALL_COUNT FCALLs, $RETURN_COUNT RETURNs"

            # Show partial trace output
            if [ -f "$SYSDIG_LOG" ] && [ -s "$SYSDIG_LOG" ]; then
                echo "  First 5 function calls:"
                grep "\[FCALL\]" "$SYSDIG_LOG" 2>/dev/null | head -5 | sed 's/^/    /'
            fi
        fi

        echo "  ================================"
    fi
done

# Step 5: Stop container
echo ""
echo "=== Step 5: Stop container ==="
cd "$TEST_CONTAINER_DIR"
docker compose down

echo ""
echo "======================================================"
echo "Tests completed!"
echo "======================================================"
echo "Log directory: $LOG_DIR"
echo ""
echo "Log files:"
ls -lh "$LOG_DIR" 2>/dev/null || echo "  (No log files)"
echo ""

# Statistical summary
if [ "$SKIP_SYSDIG" = false ]; then
    echo "Test Summary:"
    TOTAL_FCALL=0
    TOTAL_RETURN=0

    for log_file in "$LOG_DIR"/*.log; do
        if [ -f "$log_file" ]; then
            FCALL_COUNT=$(grep -c "\[FCALL\]" "$log_file" 2>/dev/null || echo "0")
            RETURN_COUNT=$(grep -c "\[RETURN\]" "$log_file" 2>/dev/null || echo "0")
            TOTAL_FCALL=$((TOTAL_FCALL + FCALL_COUNT))
            TOTAL_RETURN=$((TOTAL_RETURN + RETURN_COUNT))

            test_name=$(basename "$log_file" .log)
            printf "  %-20s FCALL: %4d  RETURN: %4d\n" "$test_name" $FCALL_COUNT $RETURN_COUNT
        fi
    done

    echo ""
    echo "  Total: FCALL: $TOTAL_FCALL  RETURN: $TOTAL_RETURN"
fi

echo "======================================================"

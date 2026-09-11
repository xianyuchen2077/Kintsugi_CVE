#!/bin/bash

# Automated test script: build, deploy, and test the tracer extension using sysdig.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_CONTAINER_DIR="$SCRIPT_DIR/container"
TEST_CONTAINER_NAME="stack-tracer-php5-test"
BUILD_SCRIPT="$SOURCE_ROOT/source/build.sh"
LOG_DIR="$SCRIPT_DIR/log"

echo "======================================================"
echo "    PHP5 Tracer Test Script"
echo "======================================================"

if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker is not running."
    exit 1
fi

if ! command -v sysdig >/dev/null 2>&1; then
    echo "ERROR: sysdig is not installed."
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script requires root privileges."
    exit 1
fi

if [ ! -d "$TEST_CONTAINER_DIR" ]; then
    echo "ERROR: Test container directory not found: $TEST_CONTAINER_DIR"
    exit 1
fi

mkdir -p "$LOG_DIR"

# Step 1: Build tracer.so
echo ""
echo "=== Step 1: Build tracer.so ==="
bash "$BUILD_SCRIPT" "$TEST_CONTAINER_DIR" "$TEST_CONTAINER_NAME"

SO_FILE="$TEST_CONTAINER_DIR/tracer.so"
if [ ! -f "$SO_FILE" ]; then
    echo "ERROR: Build failed, tracer.so not found."
    exit 1
fi
echo "Build complete: $SO_FILE"

# Step 2: Start test container
echo ""
echo "=== Step 2: Start test container ==="
cd "$TEST_CONTAINER_DIR"
docker compose down >/dev/null 2>&1 || true
docker compose up -d
sleep 10

CONTAINER_ID=$(docker ps --filter "name=$TEST_CONTAINER_NAME" --format "{{.ID}}")
if [ -z "$CONTAINER_ID" ]; then
    echo "ERROR: Failed to get container ID."
    exit 1
fi

CONTAINER_PID=$(docker inspect --format='{{.State.Pid}}' "$CONTAINER_ID")
echo "Container ID: $CONTAINER_ID, PID: $CONTAINER_PID"

# Step 3: Deploy test files
echo ""
echo "=== Step 3: Deploy test files ==="
docker exec "$CONTAINER_ID" mkdir -p /var/www/html/
docker cp "$SCRIPT_DIR/web/." "$CONTAINER_ID:/var/www/html/"
docker cp "$SCRIPT_DIR/web/11_external.php" "$CONTAINER_ID:/tmp/external_funcs.php"
docker exec "$CONTAINER_ID" chown -R www-data:www-data /var/www/html/
docker exec "$CONTAINER_ID" chown www-data:www-data /tmp/external_funcs.php
echo "Test files deployed."

# Step 4: Run tests with sysdig monitoring
echo ""
echo "=== Step 4: Run tests (sysdig monitoring) ==="

for i in {1..11}; do
    if [ -f "$SCRIPT_DIR/web/${i}.php" ]; then
        echo "Running test ${i}.php"

        SYSDIG_LOG="$LOG_DIR/${i}.log"
        echo "  Log file: $SYSDIG_LOG"

        sysdig -s 8192 -v -p "%evt.time %proc.name %evt.buffer" \
            "evt.type=write and fd.name=/dev/null" \
            > "$SYSDIG_LOG" 2>&1 &
        SYSDIG_PID=$!
        echo "  sysdig PID: $SYSDIG_PID"

        sleep 5
        echo "  Monitoring ready, executing PHP..."

        echo "  Command: docker exec $CONTAINER_ID php /var/www/html/${i}.php"
        if docker exec "$CONTAINER_ID" php /var/www/html/${i}.php; then
            echo "  PHP execution succeeded."
        else
            echo "  PHP execution failed (exit code: $?)."
        fi

        sleep 5

        kill $SYSDIG_PID
        wait $SYSDIG_PID 2>/dev/null || true

        SYSCALL_COUNT=$(wc -l < "$SYSDIG_LOG" 2>/dev/null || echo "0")
        echo "  Test ${i}: captured $SYSCALL_COUNT syscalls"

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
echo "Tests complete!"
echo "======================================================"
echo "Log directory: $LOG_DIR"
echo "Log files:"
ls -la "$LOG_DIR"/*.log 2>/dev/null || echo "  (no log files)"
echo "======================================================"

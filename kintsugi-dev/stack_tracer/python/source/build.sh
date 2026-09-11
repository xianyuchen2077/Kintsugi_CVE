#!/bin/bash

# Python Tracer Deployment Script
# Purpose: Deploy Python tracer to a specified CVE container, auto-enabled via sitecustomize
# Arguments: $1 = container name
# Note: tracer.ini config file should be mapped to /etc/tracer.ini via docker-compose volumes

set -e

CONTAINER_NAME="$1"
PYTHON_BIN="${2:-python3}"

if [ -z "$CONTAINER_NAME" ]; then
    echo "Usage: $0 <container_name> [python_path]"
    echo "Example: $0 cve-airflow-1"
    echo "Example: $0 cve-graphite-1 /opt/graphite/bin/python3"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Color output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "======================================================"
echo "    Python Tracer Deployment Script"
echo "======================================================"
echo "Container: $CONTAINER_NAME"
echo "======================================================"

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${RED}[ERROR] Container not running: $CONTAINER_NAME${NC}"
    exit 1
fi

# Copy files to container
docker exec -u root "$CONTAINER_NAME" mkdir -p /tmp/python_tracer
docker cp "$SCRIPT_DIR/tracer.py" "$CONTAINER_NAME:/tmp/python_tracer/"
docker cp "$SCRIPT_DIR/installer.py" "$CONTAINER_NAME:/tmp/python_tracer/"
echo -e "${GREEN}[OK] Files copied${NC}"

# Execute installation (requires root to write to site-packages)
echo "[INFO] Using Python: $PYTHON_BIN"
docker exec -u root "$CONTAINER_NAME" "$PYTHON_BIN" /tmp/python_tracer/installer.py
echo -e "${GREEN}[OK] Installation complete${NC}"

# Verify (using the same Python to verify module can be loaded)
docker exec "$CONTAINER_NAME" "$PYTHON_BIN" -c "import tracer; print('[OK] tracer module loaded')"

echo "======================================================"
echo -e "${GREEN}Deployment finished!${NC}"
echo "Config file: /etc/tracer.ini (mapped via docker-compose volumes)"
echo "======================================================"

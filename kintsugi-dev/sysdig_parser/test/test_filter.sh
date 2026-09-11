#!/bin/bash

# Test script for filter.lua functionality
# Runs comprehensive tests and provides detailed output

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Sysdig Filter Test Suite${NC}"
echo -e "${BLUE}========================================${NC}"
echo

# Check if Lua is installed
if ! command -v lua >/dev/null 2>&1; then
    echo -e "${RED}Error: Lua is not installed or not in PATH${NC}"
    echo "Please install Lua to run the tests."
    exit 1
fi

echo -e "${YELLOW}Checking dependencies...${NC}"

# Check if MessagePack.lua exists
if [[ ! -f "$PARENT_DIR/MessagePack.lua" ]]; then
    echo -e "${RED}Error: MessagePack.lua not found in parent directory${NC}"
    exit 1
fi

# Check if fields.config exists
if [[ ! -f "$PARENT_DIR/fields.config" ]]; then
    echo -e "${RED}Error: fields.config not found in parent directory${NC}"
    exit 1
fi

# Check if filter.lua exists
if [[ ! -f "$PARENT_DIR/filter.lua" ]]; then
    echo -e "${RED}Error: filter.lua not found in parent directory${NC}"
    exit 1
fi

# Check if test_filter.lua exists
if [[ ! -f "$SCRIPT_DIR/test_filter.lua" ]]; then
    echo -e "${RED}Error: test_filter.lua not found${NC}"
    exit 1
fi

echo -e "${GREEN}✓ All dependencies found${NC}"
echo

# Make test script executable
chmod +x "$SCRIPT_DIR/test_filter.lua"

# Run the Lua tests
echo -e "${YELLOW}Running Lua tests...${NC}"
echo

# Change to parent directory so filter.lua can find fields.config in current directory
cd "$PARENT_DIR"
if lua test/test_filter.lua; then
    echo
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}   All tests PASSED! ✓${NC}"
    echo -e "${GREEN}========================================${NC}"
    exit 0
else
    echo
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}   Some tests FAILED! ✗${NC}"
    echo -e "${RED}========================================${NC}"
    echo
    echo -e "${YELLOW}Debugging information:${NC}"
    echo -e "  - Test directory: ${SCRIPT_DIR}"
    echo -e "  - Parent directory: ${PARENT_DIR}"
    echo -e "  - Lua version: $(lua -v)"
    echo
    exit 1
fi
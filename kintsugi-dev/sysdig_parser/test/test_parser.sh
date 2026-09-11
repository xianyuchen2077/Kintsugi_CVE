#!/bin/bash

# Test script for sysdig parser - complete pipeline test

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."  # Switch to project root directory

# Source conda if needed (comment out if not using conda)
if [ -f ~/.bashrc ]; then
    source ~/.bashrc
    eval "$(conda shell.bash hook)" 2>/dev/null || true
fi

PARSER_DIR="$(pwd)"

echo "======================================================="
echo "Sysdig Parser Complete Test"
echo "======================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_error() { echo -e "${RED}✗ $1${NC}"; }
print_info() { echo -e "${YELLOW}ℹ $1${NC}"; }

# Function to cleanup test files
cleanup() {
    print_info "Cleaning up test files..."
    # Clean test output
    rm -f "test/test_output.jsonl"
    
    # Clean any temporary files that might remain (in case of test failure)
    if [ -f "test/sample.scap" ]; then
        SAMPLE_BASE="sample"
        rm -f test/${SAMPLE_BASE}.scap[0-9]* 2>/dev/null || true
        rm -f test/${SAMPLE_BASE}.[0-9]*.gz 2>/dev/null || true
    fi
}

# Trap to ensure cleanup on exit
trap cleanup EXIT

echo "Checking required files..."

# Check for sample.scap
if [ ! -f "test/sample.scap" ]; then
    print_error "sample.scap not found in test directory"
    exit 1
fi
print_success "Found sample.scap file"

# Check for filter.lua
if [ ! -f "filter.lua" ]; then
    print_error "filter.lua not found in project root"
    print_info "Please ensure filter.lua exists before running tests"
    exit 1
fi
print_success "Found filter.lua file"

echo ""
echo "Running complete parsing test..."
echo "--------------------------------"

if python3 test/test_parser.py; then
    print_success "Complete parsing test passed"
    
    # Show output file info if it exists
    if [ -f "test/test_output.jsonl" ]; then
        LINES=$(wc -l < "test/test_output.jsonl")
        print_info "Generated JSONL file with $LINES events"
        
        # Only show sample if file is not empty
        if [ "$LINES" -gt 0 ]; then
            print_info "Sample output (first event):"
            head -n 1 "test/test_output.jsonl" | python3 -m json.tool 2>/dev/null | head -n 20 || print_info "Could not format JSON"
        fi
    fi
else
    print_error "Complete parsing test failed"
    exit 1
fi

echo ""
echo "======================================================="
print_success "Parser successfully processed scap file and generated JSONL output!"
echo "======================================================="
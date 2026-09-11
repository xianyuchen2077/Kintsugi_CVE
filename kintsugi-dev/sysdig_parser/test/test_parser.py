#!/usr/bin/env python3

import json
from pathlib import Path
import sys

# Add parent directory to path to import the processor
sys.path.append(str(Path(__file__).parent.parent))

from parser import SysdigProcessor


def test_complete_parsing():
    """Test complete parsing pipeline with real scap file"""
    print("Testing complete parsing pipeline...")
    
    # Use the real sample.scap file
    sample_scap = Path(__file__).parent / "sample.scap"
    if not sample_scap.exists():
        print("✗ sample.scap not found, skipping test")
        return False
    
    try:
        # Initialize processor with real scap file
        processor = SysdigProcessor(str(sample_scap))
        print(f"✓ Parser initialized with {len(processor.fields)} fields")
        print(f"✓ Using {processor.cpu_count} CPU cores for processing")
        
        # Run the complete processing pipeline
        output_file = Path(__file__).parent / "test_output.jsonl"
        processor.process_sysdig_data(str(output_file))
        
        # Verify output file was created
        if not output_file.exists():
            print("✗ Output file was not created")
            return False
        
        # Check output file content
        line_count = 0
        with open(output_file, 'r') as f:
            for line in f:
                line_count += 1
                if line_count <= 3:  # Show first few lines
                    try:
                        data = json.loads(line.strip())
                        print(f"✓ Line {line_count}: {len(data)} fields")
                    except json.JSONDecodeError as e:
                        print(f"✗ Invalid JSON on line {line_count}: {e}")
                        return False
        
        print(f"✓ Complete parsing successful: {line_count} events processed")
        
        # Verify cleanup happened
        temp_files_cleaned = True
        sample_base = sample_scap.stem
        sample_dir = sample_scap.parent
        
        # Check if temp files were cleaned
        for i in range(100):  # Check first 100 possible indices
            if (sample_dir / f"{sample_base}.scap{i}").exists():
                print(f"✗ Temporary file {sample_base}.scap{i} was not cleaned")
                temp_files_cleaned = False
                break
            if (sample_dir / f"{sample_base}.{i}.gz").exists():
                print(f"✗ Temporary file {sample_base}.{i}.gz was not cleaned")
                temp_files_cleaned = False
                break
            # If we don't find any files at index i, we've likely checked all
            if i > 0 and not (sample_dir / f"{sample_base}.scap{i-1}").exists():
                break
        
        if temp_files_cleaned:
            print("✓ Temporary files were properly cleaned up")
        
        return True
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"✗ Complete parsing test failed: {e}")
        return False


def main():
    """Run parsing test"""
    print("Starting sysdig parser complete test...")
    print("=" * 50)
    
    success = test_complete_parsing()
    
    print("=" * 50)
    if success:
        print("✓ Test PASSED: Parser can successfully process scap file and generate JSONL output")
    else:
        print("✗ Test FAILED: Parser failed to complete processing")
    
    return success


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
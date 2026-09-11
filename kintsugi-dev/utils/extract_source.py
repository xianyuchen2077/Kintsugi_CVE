"""
Extract unique source code and payloads from callstack_with_code
"""

import json
import argparse
from pathlib import Path
from typing import Dict, Set
import sys


def extract_source_and_payload(cve: str):
    """
    Extract source code and payloads for the specified CVE.

    Args:
        cve: CVE identifier, e.g. CVE-2018-1000533
    """
    input_dir = Path(f"data/{cve}/callstack_with_code")
    output_dir = Path(f"data/{cve}/source_code")

    if not input_dir.exists():
        print(f"Error: directory not found {input_dir}")
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"Output directory: {output_dir}")

    json_files = sorted(input_dir.glob("*.json"))
    if not json_files:
        print(f"Error: no JSON files found in {input_dir}")
        sys.exit(1)

    print(f"Found {len(json_files)} JSON files")

    for json_file in json_files:
        print(f"\nProcessing: {json_file.name}")

        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            print(f"Failed to read {json_file.name}: {e}")
            continue

        if not isinstance(data, list):
            print(f"Warning: {json_file.name} is not an array")
            continue

        seen_functions: Set[str] = set()
        unique_functions = []
        payload = None

        for entry in data:
            if payload is None and 'payload' in entry:
                payload = entry['payload']

            if 'function' in entry:
                func = entry['function']
                func_name = func.get('name', '')
                source_code = func.get('source_code', '')

                if not func_name or not source_code:
                    continue

                if func_name not in seen_functions:
                    seen_functions.add(func_name)
                    unique_functions.append({
                        'name': func_name,
                        'path': func.get('definition_path', func.get('path', '')),
                        'start': func.get('definition_start', ''),
                        'end': func.get('definition_end', ''),
                        'source_code': source_code
                    })

        output_filename = json_file.stem + ".txt"
        output_path = output_dir / output_filename

        with open(output_path, 'w', encoding='utf-8') as f:
            for func in unique_functions:
                f.write(f"=== Function: {func['name']} ===\n")
                if func['path']:
                    f.write(f"File: {func['path']}\n")
                if func['start'] and func['end']:
                    f.write(f"Lines: {func['start']}-{func['end']}\n")
                f.write("\n")
                f.write(func['source_code'])
                f.write("\n\n")

            if payload:
                f.write("=== PAYLOAD ===\n")
                f.write(payload)
                f.write("\n")

        print(f"  Extracted {len(unique_functions)} unique functions")
        print(f"  Output: {output_path}")

    print(f"\nDone! All files output to: {output_dir}")


def main():
    parser = argparse.ArgumentParser(
        description="Extract unique source code and payloads from callstack_with_code"
    )
    parser.add_argument(
        "--cve",
        required=True,
        help="CVE identifier, e.g. CVE-2018-1000533"
    )

    args = parser.parse_args()
    extract_source_and_payload(args.cve)


if __name__ == "__main__":
    main()

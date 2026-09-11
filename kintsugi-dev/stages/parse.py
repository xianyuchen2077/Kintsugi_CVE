import logging
import sys
import traceback
import argparse
from pathlib import Path
from sysdig_parser.parser import SysdigProcessor

logger = logging.getLogger(__name__)


def parse_sysdig(cve):
    """
    Parse sysdig capture files to JSONL format

    Args:
        cve: CVEConfig object

    Returns:
        bool: True if successful, False otherwise
    """
    data_dir = cve.data_dir

    # Process both files
    files_to_process = [
        ("normal.scap", "normal.jsonl"),
        ("malicious.scap", "malicious.jsonl")
    ]

    processed_files = 0

    for input_file, output_file in files_to_process:
        input_path = data_dir / input_file
        output_path = data_dir / output_file

        logger.info(f"Processing {input_path} -> {output_path}")

        try:
            # Initialize processor
            processor = SysdigProcessor(str(input_path))

            # Process the file
            processor.process_sysdig_data(str(output_path))
            processed_files += 1
            logger.info(f"Successfully processed {input_file}")

        except FileNotFoundError:
            logger.warning(f"{input_path} not found, skipping...")
        except Exception as e:
            traceback.print_exc()
            logger.error(f"Error processing {input_file}: {e}")

    if processed_files > 0:
        logger.info(f"Parsing completed. Processed {processed_files} files.")
        return True
    else:
        logger.error("No files were processed successfully.")
        return False


if __name__ == "__main__":
    from config import load_cve_config

    parser = argparse.ArgumentParser(
        description='Parse sysdig capture files to JSONL format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 parse.py --cve CVE-2021-26120

Requirements:
  - sysdig-parser directory in project root
  - Raw .scap files in data/{cve}/raw/ directory
        """
    )
    parser.add_argument('--cve', required=True,
                        help='CVE number (e.g., CVE-2021-26120)')

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%H:%M:%S",
    )

    cve = load_cve_config(args.cve)
    success = parse_sysdig(cve)

    if success:
        logger.info("Script completed successfully")
        sys.exit(0)
    else:
        logger.error("Script failed")
        sys.exit(1)
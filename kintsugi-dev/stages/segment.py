"""
CVE-agnostic request unit splitter
Handles directory traversal and calls CVE-specific file processing
"""

import logging
import sys
import argparse
import importlib
from pathlib import Path
import docker

logger = logging.getLogger(__name__)


def load_cve_splitter(cve):
    """
    Dynamically load CVE-specific splitter module

    Args:
        cve: CVEConfig object

    Returns:
        module: CVE-specific splitter module
    """
    try:
        module_path = f"cves.{cve.language}.{cve.cve_id}.unit"
        return importlib.import_module(module_path)
    except ImportError as e:
        raise ImportError(f"Cannot load splitter for {cve.cve_id}: {e}")


def get_container_id(container_name):
    """
    Get container ID from container name

    Args:
        container_name (str): Docker container name

    Returns:
        str: Container ID (short form) or None if not found
    """
    try:
        client = docker.from_env()
        container = client.containers.get(container_name)
        # Return short container ID (first 12 characters)
        return container.id[:12]
    except docker.errors.NotFound:
        logger.warning(f"Container {container_name} not found")
        return None
    except Exception as e:
        logger.warning(f"Failed to connect to Docker: {e}")
        return None


def split_units(cve):
    """
    Split request units for a specific CVE

    Args:
        cve: CVEConfig object

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Load CVE-specific splitter
        splitter_module = load_cve_splitter(cve)

        # Use data_dir from CVE config
        input_dir = cve.data_dir
        output_dir = cve.data_dir / "unit"

        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)

        # Get all JSONL files
        jsonl_files = list(input_dir.glob("*.jsonl"))

        if not jsonl_files:
            logger.error(f"No JSONL files found in {input_dir}")
            return False

        logger.info(f"Starting unit splitting for {cve.cve_id}")
        logger.info(f"Input directory: {input_dir}")
        logger.info(f"Output directory: {output_dir}")
        logger.info(f"Found {len(jsonl_files)} JSONL files to process")

        # Get container ID from CVE config
        container_id = None
        if cve.container:
            container_id = get_container_id(cve.container)
            if container_id:
                logger.info(f"Container filter: {cve.container} (ID: {container_id})")
            else:
                logger.warning("Proceeding without container filtering")

        total_requests = 0
        global_id = 0

        # Process each file using CVE-specific logic
        for jsonl_file in sorted(jsonl_files):
            if hasattr(splitter_module, 'process_file'):
                file_requests = splitter_module.process_file(
                    str(jsonl_file),
                    str(output_dir),
                    global_id,
                    container_id=container_id
                )
                total_requests += file_requests
                global_id += file_requests
            else:
                logger.error(f"process_file function not found in {cve.cve_id} splitter")
                return False

        logger.info("=== Processing Complete ===")
        logger.info(f"Total files processed: {len(jsonl_files)}")
        logger.info(f"Total requests extracted: {total_requests}")
        logger.info(f"Output directory: {output_dir}")
        return True

    except ImportError as e:
        logger.error(f"Error loading CVE splitter: {e}")
        return False
    except Exception as e:
        logger.error(f"Error during unit splitting: {e}")
        return False

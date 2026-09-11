#!/usr/bin/env python3

import sys
import gzip
import json
import multiprocessing
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Generator, Dict, Optional

import msgpack
from tqdm import tqdm


script_dir = Path(__file__).parent
config_file = script_dir / "fields.config"


class SysdigProcessor:
    def __init__(self, capture_path: str):
        self.capture_path = Path(capture_path).resolve()
        self.capture_dir = self.capture_path.parent
        self.base_name = self.capture_path.stem
        self.work_dir = self.capture_dir / f".{self.base_name}_sysdig_chunks"
        
        # CPU count for parallel processing
        cpu_count = os.cpu_count()
        if cpu_count is None:
            raise ValueError("Cannot determine CPU count")
        self.cpu_count = int(cpu_count)
        
        # Load field names from configuration file
        with open(config_file, 'r') as f:
            self.fields = [line.strip() for line in f if line.strip()]
        
        # Processing state for virtual IDs
        self.subproc_dict = {}
        self.subthread_dict = {}
        self.tid_vtid_dict = {}
        self.vtid_ptid_dict = {}
        
        # Track temporary files for cleanup
        self.temp_files = []

    def split_scap_file(self) -> int:
        """Split the main scap file into smaller chunks (32MB each)."""
        print(f"Splitting {self.capture_path} into 32MB chunks...")
        
        # Clean up any existing temporary files
        self.cleanup_temp_files()
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        # Split the scap file using sysdig
        # Output will be xxx.0.scap, xxx.1.scap, etc.
        output_prefix = self.work_dir / self.base_name
        command = [
            "sysdig",
            "-r", str(self.capture_path),
            "-C", "32MB",  # Split into 32MB chunks
            "-w", f"{output_prefix}.scap"
        ]
        
        result = subprocess.run(
            command,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stdin=subprocess.DEVNULL
        )
        if result.returncode != 0:
            print(f"Warning: sysdig split command returned {result.returncode}")
            print(f"stderr: {result.stderr.decode()}")
        
        # Count generated files and track them
        idx = 0
        while True:
            scap_file = self.work_dir / f"{self.base_name}.scap{idx}"
            if scap_file.exists():
                self.temp_files.append(scap_file)
                idx += 1
            else:
                break
        
        print(f"Created {idx} split files")
        return idx

    @staticmethod
    def process_single_scap(args):
        """Process a single scap file with lua script and compress output."""
        idx, work_dir, base_name, script_dir = args
        
        scap_path = work_dir / f"{base_name}.scap{idx}"
        gz_path = work_dir / f"{base_name}.{idx}.gz"
        lua_script = script_dir / "filter.lua"
        
        try:
            # Run sysdig with lua script
            command = [
                "sysdig",
                "-r", str(scap_path),
                "-c", str(lua_script)
            ]
            
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                cwd=str(script_dir)
            )
            
            if result.returncode != 0:
                print(f"Error processing chunk {idx}: {result.stderr.decode()}")
                return False
            
            # Compress and save output
            with gzip.open(gz_path, 'wb') as f:
                f.write(result.stdout)
            
            return True
            
        except Exception as e:
            print(f"Exception processing chunk {idx}: {e}")
            return False

    def process_scap_parallel(self, num_files: int):
        """Process all scap files in parallel using process pool."""
        print(f"Processing {num_files} files with {self.cpu_count} processes...")
        
        # Track gz files for cleanup
        for idx in range(num_files):
            gz_file = self.work_dir / f"{self.base_name}.{idx}.gz"
            self.temp_files.append(gz_file)
        
        # Prepare arguments for all files
        args_list = [
            (idx, self.work_dir, self.base_name, script_dir) 
            for idx in range(num_files)
        ]
        
        # Use process pool to process all files
        # The pool will automatically manage the number of concurrent processes
        with multiprocessing.Pool(processes=self.cpu_count) as pool:
            # Use imap for progress tracking
            results = list(tqdm(
                pool.imap(self.process_single_scap, args_list),
                total=num_files,
                desc="Processing files"
            ))
            
            # Check for failures
            failed_indices = [i for i, success in enumerate(results) if not success]
            if failed_indices:
                print(f"Warning: Failed to process chunks: {failed_indices}")

    def load_gz_file(self, idx: int) -> Generator[Dict, None, None]:
        """Load and decompress a single gz file in chunks."""
        gz_path = self.work_dir / f"{self.base_name}.{idx}.gz"
        
        if not gz_path.exists():
            print(f"Warning: {gz_path} does not exist")
            return
        
        with gzip.open(gz_path, 'rb') as f:
            unpacker = msgpack.Unpacker(raw=False, strict_map_key=False)
            while True:
                # Read in 50MB chunks
                data = f.read(50 * 1024 * 1024)
                if not data:
                    break
                unpacker.feed(data)
                for obj in unpacker:
                    yield obj

    def load_all_events(self) -> Generator[Dict, None, None]:
        """Load all events from all gz files in order."""
        # Count available gz files
        idx = 0
        while (self.work_dir / f"{self.base_name}.{idx}.gz").exists():
            idx += 1
        
        if idx == 0:
            print("No gz files found to process")
            return
        
        print(f"Loading events from {idx} gz files...")
        
        evt_num = 0
        for file_idx in range(idx):
            gen = self.load_gz_file(file_idx)
            
            # First object is the field names
            field_names = next(gen, None)
            if field_names is None:
                continue
            
            # Process remaining objects as events
            for obj_ in gen:
                # Convert indexed data back to field names
                if isinstance(obj_, list):
                    obj = {field_names[i-1]: obj_[i] for i in range(len(obj_))}
                else:
                    obj = {field_names[i-1]: obj_[i] for i in obj_.keys()}
                    obj.update({key: None for key in field_names if key not in obj})
                
                obj["evt.num"] = evt_num
                evt_num += 1
                yield obj

    def process_event(self, obj: dict) -> Optional[Dict]:
        """Process individual event with business logic."""
        try:
            # Initialize virtual IDs
            obj["proc.cvpid"] = None
            obj["proc.vpid"] = str(obj["proc.vpid"]) if obj.get("proc.vpid") else None
            obj["proc.pvpid"] = str(obj["proc.pvpid"]) if obj.get("proc.pvpid") else None
            
            obj["thread.vtid"] = str(obj["thread.vtid"]) if obj.get("thread.vtid") else None
            obj["thread.tid"] = str(obj["thread.tid"]) if obj.get("thread.tid") else None
            obj["thread.cvtid"] = None
            obj["thread.pvtid"] = None
            
            # Handle process creation events
            if obj.get("evt.type") in ["vfork", "clone", "clone3"]:
                if not self._handle_process_creation(obj):
                    return None
            
            # Update process and thread IDs with virtual tracking
            self._update_virtual_ids(obj)
            
            # Ensure filesystem fields exist
            for field in ["fs.path.name", "fs.path.source", "fs.path.target"]:
                if field not in obj:
                    obj[field] = None
            
            # Convert port numbers to strings
            if obj.get("fd.cport") is not None:
                obj["fd.cport"] = str(int(obj["fd.cport"]))
            else:
                obj["fd.cport"] = None
                
            if obj.get("fd.sport") is not None:
                obj["fd.sport"] = str(int(obj["fd.sport"]))
            else:
                obj["fd.sport"] = None
            
            # Return required fields plus virtual fields
            result = {key: obj.get(key) for key in self.fields}
            
            # Add virtual fields that are computed in Python
            virtual_fields = ["proc.cvpid", "thread.cvtid", "thread.pvtid"]
            for field in virtual_fields:
                result[field] = obj.get(field)
            
            return result
            
        except Exception as e:
            print(f"Error processing event: {e}")
            print(f"Event data: {json.dumps(obj)}")
            raise

    def _handle_process_creation(self, obj: dict) -> bool:
        """Handle vfork/clone/clone3 events."""
        evt_info = obj.get("evt.info", "")
        if not evt_info or not evt_info.startswith("res="):
            return False
        
        res_match = re.search(r"res=(-?\d+)", evt_info)
        if not res_match:
            return False
        
        res = int(res_match.group(1))
        res_str = str(res)
        
        if res < 0:
            return False
        elif res == 0:
            # Child process
            vtid = obj["thread.vtid"]
            ptid_match = re.search(r"ptid=(\d+)", evt_info)
            if ptid_match and obj.get("evt.type") == "vfork":
                ptid = ptid_match.group(1)
                self.subthread_dict[vtid] = self.subthread_dict.get(vtid, 0) + 1
                obj["thread.vtid"] = f"{vtid}.{self.subthread_dict[vtid]}"
                self.vtid_ptid_dict[obj["thread.vtid"]] = ptid
            return False
        else:
            # Parent process with child PID
            self.subproc_dict[res_str] = self.subproc_dict.get(res_str, 0) + 1
            obj["proc.cvpid"] = f"{res_str}.{self.subproc_dict[res_str]}"
            
            if obj.get("evt.type") == "vfork":
                obj["thread.cvtid"] = f"{res_str}.{self.subproc_dict[res_str]}"
            else:
                self.subthread_dict[res_str] = self.subthread_dict.get(res_str, 0) + 1
                obj["thread.cvtid"] = f"{res_str}.{self.subthread_dict[res_str]}"
                self.vtid_ptid_dict[obj["thread.cvtid"]] = obj["thread.tid"]
        
        return True

    def _update_virtual_ids(self, obj: dict):
        """Update virtual process and thread IDs."""
        # Update process virtual IDs
        if obj.get("proc.vpid") and obj["proc.vpid"] in self.subproc_dict:
            obj["proc.vpid"] = f"{obj['proc.vpid']}.{self.subproc_dict[obj['proc.vpid']]}"
        if obj.get("proc.pvpid") and obj["proc.pvpid"] in self.subproc_dict:
            obj["proc.pvpid"] = f"{obj['proc.pvpid']}.{self.subproc_dict[obj['proc.pvpid']]}"
        
        # Update thread virtual IDs
        if obj.get("thread.vtid") and obj["thread.vtid"] in self.subthread_dict:
            obj["thread.vtid"] = f"{obj['thread.vtid']}.{self.subthread_dict[obj['thread.vtid']]}"
        
        # Track TID to VTID mapping
        if obj.get("thread.tid") and obj.get("thread.vtid"):
            self.tid_vtid_dict[obj["thread.tid"]] = obj["thread.vtid"]
        
        # Set parent thread virtual ID
        if obj.get("thread.vtid") and obj["thread.vtid"] in self.vtid_ptid_dict:
            parent_tid = self.vtid_ptid_dict[obj["thread.vtid"]]
            obj["thread.pvtid"] = self.tid_vtid_dict.get(parent_tid)
        
        # Update parent thread virtual ID if it has sub-threads
        if obj.get("thread.pvtid") and obj["thread.pvtid"] in self.subthread_dict:
            obj["thread.pvtid"] = f"{obj['thread.pvtid']}.{self.subthread_dict[obj['thread.pvtid']]}"

    def cleanup_temp_files(self):
        """Clean up all temporary files created during processing."""
        print("Cleaning up temporary files...")
        for temp_file in self.temp_files:
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except Exception as e:
                    print(f"Warning: Failed to delete {temp_file}: {e}")
        self.temp_files.clear()
        if self.work_dir.exists():
            try:
                shutil.rmtree(self.work_dir)
            except Exception as e:
                print(f"Warning: Failed to delete {self.work_dir}: {e}")

    def process_sysdig_data(self, output_file):
        """Main processing pipeline with parallel processing."""
        try:
            print("Starting sysdig data processing with multiprocessing...")
            
            # Step 1: Split the scap file into chunks
            num_files = self.split_scap_file()
            if num_files == 0:
                raise RuntimeError("Failed to split scap file")
            
            # Step 2: Process all chunks in parallel
            self.process_scap_parallel(num_files)
            
            # Step 3: Setup output file
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Step 4: Load all events and process them sequentially
            # (Sequential processing is required to maintain event order and state)
            processed_count = 0
            with open(output_path, 'w') as out_file:
                for event in tqdm(self.load_all_events(), desc="Processing events"):
                    processed_event = self.process_event(event)
                    if processed_event:
                        out_file.write(json.dumps(processed_event) + '\n')
                        processed_count += 1
            
            print(f"Processing complete. {processed_count} events written to {output_path}")
            
        finally:
            # Always cleanup temporary files, even if an error occurs
            self.cleanup_temp_files()


def main():
    # Default paths
    if len(sys.argv) > 1:
        capture_file = sys.argv[1]
    else:
        capture_file = "./capture_dir/capture.scap"
    
    if len(sys.argv) > 2:
        output_file = sys.argv[2]
    else:
        output_file = "./capture/capture.jsonl"
    
    processor = SysdigProcessor(capture_file)
    processor.process_sysdig_data(output_file)


if __name__ == "__main__":
    main()

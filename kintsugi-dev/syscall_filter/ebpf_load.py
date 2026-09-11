#!/usr/bin/env python3
"""
ebpf_load.py - Simple eBPF Loader

Responsibilities:
1. Load syscalls from syscalls.yaml
2. Generate eBPF C code
3. Load eBPF program into kernel
4. Keep program running
"""

import os
import sys
import yaml

from bcc import BPF

from ebpf_code_gen import EBPFCodeGenerator


def load_syscalls_from_yaml():
    """Load syscall list from syscalls.yaml

    Returns:
        list: Syscall names, with 'prctl' excluded (used for control plane)
    """
    # Get path to syscalls.yaml (one level up from this script)
    yaml_path = os.path.join(os.path.dirname(__file__), "..", "config", "syscalls.yaml")

    if not os.path.exists(yaml_path):
        print(f"[-] Error: syscalls.yaml not found at {yaml_path}")
        sys.exit(1)

    with open(yaml_path, "r") as f:
        config = yaml.safe_load(f)

    if "syscalls" not in config:
        print("[-] Error: 'syscalls' key not found in syscalls.yaml")
        sys.exit(1)

    # Exclude 'prctl' - it's used for control plane communication (CMD_FILTER_BEGIN/END)
    # and is automatically added to whitelist during filter_begin
    syscalls = [sc for sc in config["syscalls"] if sc != "prctl"]

    return syscalls


class EBPFLoader:
    """Simple eBPF loader"""

    def __init__(self):
        self.bpf = None

    def load(self):
        """Load eBPF program"""
        print("=" * 60)
        print("eBPF Loader")
        print("=" * 60)

        # Load syscalls from YAML
        print("\n[*] Loading syscall list from syscalls.yaml...")
        syscalls = load_syscalls_from_yaml()
        print(f"[+] Loaded {len(syscalls)} syscalls (prctl excluded for control plane)")

        # Generate eBPF C code
        print(f"\n[*] Generating eBPF code for {len(syscalls)} syscalls...")
        generator = EBPFCodeGenerator(syscalls)
        c_code = generator.generate()
        print(f"[+] Generated {len(c_code)} bytes of C code")

        # Load into kernel
        print("\n[*] Loading eBPF program into kernel...")
        try:
            self.bpf = BPF(text=c_code, debug=0xf)
            print("[+] eBPF program loaded successfully")
        except Exception as e:
            print(f"[-] Failed to load eBPF program: {e}")
            raise

        try:
            self.bpf.get_table("target_ids")
            self.bpf.get_table("thr_wlist")
            print(
                "[+] BPF maps 'target_ids' and 'thr_wlist' are present in the kernel."
            )
        except KeyError as e:
            print(f"[-] Error: BPF map not found: {e}")
            raise

        print("\n" + "=" * 60)
        print("[+] eBPF Program Ready")
        print("=" * 60)
        print("\nControl plane is active via prctl(999, ...).")
        print("PHP extension will communicate with the kernel directly.")
        print("\nView blocked syscalls:")
        print("  sudo cat /sys/kernel/debug/tracing/trace_pipe")

    def run(self):
        """Keep program running"""
        print("\n" + "=" * 60)
        print("Monitoring Active")
        print("=" * 60)
        print("Press Ctrl+C to exit and unload eBPF program\n")

        try:
            import time

            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\n[+] Shutting down...")

        print("[+] eBPF program unloaded")


def main():
    # Check root
    if os.geteuid() != 0:
        print("[-] Root privileges required")
        print("    Usage: sudo python3 ebpf_load.py")
        sys.exit(1)

    # Load and run
    loader = EBPFLoader()
    loader.load()
    loader.run()


if __name__ == "__main__":
    main()

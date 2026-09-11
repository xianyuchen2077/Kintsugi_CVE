"""
Configuration loader
"""

import yaml
from pathlib import Path
from dataclasses import dataclass
from typing import Optional


@dataclass
class CVEConfig:
    cve_id: str
    language: str
    version: int
    container: str
    port: int
    use_whitelist: bool
    manual_install: bool
    filter_irrelevant: bool = True
    backtrack_repair: Optional[int] = None
    use_attack_flag: bool = True
    repair_method: str = "auto"
    python_path: Optional[str] = None
    ready_paths: Optional[list[str]] = None
    require_ready: bool = False

    @property
    def env_dir(self) -> Path:
        return Path(f"cves/{self.language}/{self.cve_id}/env")

    @property
    def data_dir(self) -> Path:
        return Path(f"data/{self.language}/{self.cve_id}")


def load_cve_config(cve_id: str) -> CVEConfig:
    """
    Load configuration for the specified CVE.

    Args:
        cve_id: CVE identifier, e.g. CVE-2015-8562

    Returns:
        CVEConfig object
    """
    config_path = Path(__file__).parent / "config" / "cves.yaml"
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    if cve_id not in config["cves"]:
        raise ValueError(f"CVE config not found: {cve_id}")

    cve = config["cves"][cve_id]
    return CVEConfig(
        cve_id=cve_id,
        language=cve["language"],
        version=cve["version"],
        container=cve["container"],
        port=cve["port"],
        use_whitelist=cve["use_whitelist"],
        manual_install=cve["manual_install"],
        filter_irrelevant=cve.get("filter_irrelevant", True),
        backtrack_repair=cve.get("backtrack_repair"),
        use_attack_flag=cve.get("use_attack_flag", True),
        repair_method=cve.get("repair_method", "auto"),
        python_path=cve.get("python_path"),
        ready_paths=cve.get("ready_paths"),
        require_ready=cve.get("require_ready", False),
    )


def list_cves() -> list[str]:
    config_path = Path(__file__).parent / "config" / "cves.yaml"
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    return list(config["cves"].keys())


def load_syscalls() -> list[str]:
    config_path = Path(__file__).parent / "config" / "syscalls.yaml"
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    return config["syscalls"]

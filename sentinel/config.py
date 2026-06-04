"""Configuration loader for sentinel. Reads from sentinel.yaml in CWD,
then ~/.config/sentinel/config.yaml, then falls back to built-in defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


@dataclass
class Config:
    beacon_window_sec: float = 60.0
    beacon_jitter_threshold: float = 0.15
    beacon_sample_rate_sec: float = 2.0
    c2_ports: list[int] = field(default_factory=lambda: [
        4444, 5555, 6666, 1177, 3127, 9999, 31337, 12345, 54321,
        8888, 1080, 4443, 8443, 2222,
    ])
    severity_exit_threshold: str = "high"
    scan_timeout_sec: float = 300.0
    excluded_processes: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    output_format: str = "text"
    verbosity: int = 1
    log_file: str = ""


def _find_config_file() -> Path | None:
    candidates = [
        Path.cwd() / "sentinel.yaml",
        Path.cwd() / "sentinel.yml",
        Path.home() / ".config" / "sentinel" / "config.yaml",
    ]
    env_path = os.environ.get("SENTINEL_CONFIG")
    if env_path:
        candidates.insert(0, Path(env_path))
    for p in candidates:
        if p.is_file():
            return p
    return None


def load_config(path: str | Path | None = None) -> Config:
    cfg = Config()
    if path is not None:
        config_path = Path(path)
    else:
        config_path = _find_config_file()
    if config_path is None or not config_path.is_file():
        return cfg
    if not HAS_YAML:
        return cfg
    with open(config_path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if not isinstance(raw, dict):
        return cfg
    field_map = {
        "beacon_window_sec": float,
        "beacon_jitter_threshold": float,
        "beacon_sample_rate_sec": float,
        "c2_ports": list,
        "severity_exit_threshold": str,
        "scan_timeout_sec": float,
        "excluded_processes": list,
        "excluded_paths": list,
        "output_format": str,
        "verbosity": int,
        "log_file": str,
    }
    for key, expected_type in field_map.items():
        if key in raw:
            val = raw[key]
            if isinstance(val, expected_type):
                setattr(cfg, key, val)
            elif expected_type is float and isinstance(val, (int, float)):
                setattr(cfg, key, float(val))
    return cfg

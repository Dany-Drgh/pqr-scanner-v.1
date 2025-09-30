from __future__ import annotations
from pathlib import Path
import yaml
from typing import Dict, Any


def load_repo_config(root: Path) -> Dict[str, Any]:
    """
    Load .pqrrc.yaml or .pqrrc.yml from the repo root, if present.
    """
    for name in (".pqrrc.yaml", ".pqrrc.yml"):
        p = root / name
        if p.exists():
            return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return {}

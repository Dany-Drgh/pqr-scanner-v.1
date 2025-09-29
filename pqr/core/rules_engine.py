from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any
import yaml

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


def _resolve_pack_dir(label: str) -> Path:
    idx_path = RULES_DIR / "index.yaml"
    index = yaml.safe_load(idx_path.read_text(encoding="utf-8"))
    if label == "latest":
        label = index.get("latest", "v0.1")
    return RULES_DIR / label


def _collect_yaml_files(pack_dir: Path):
    # Load both .yml and .yaml
    return sorted(list(pack_dir.glob("*.yml")) + list(pack_dir.glob("*.yaml")))


def load_rules(label: str) -> List[Dict[str, Any]]:
    pack_dir = _resolve_pack_dir(label)
    rules: List[Dict[str, Any]] = []
    yfiles = _collect_yaml_files(pack_dir)
    if not yfiles:
        return []  # nothing to load

    for y in yfiles:
        text = y.read_text(encoding="utf-8")
        # Support multi-document yaml (--- ... --- ...)
        for doc in yaml.safe_load_all(text):
            if not doc:
                continue
            if isinstance(doc, list):
                rules.extend(doc)
            elif isinstance(doc, dict):
                # allow either a single rule or {rules: [...]}
                if "rules" in doc and isinstance(doc["rules"], list):
                    rules.extend(doc["rules"])
                else:
                    rules.append(doc)
            # other node types are ignored
    return rules

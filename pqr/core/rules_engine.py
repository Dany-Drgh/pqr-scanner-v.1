from __future__ import annotations
from pathlib import Path
import yaml

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"

def _resolve_pack_dir(label: str) -> Path:
    idx_path = RULES_DIR / "index.yaml"
    index = yaml.safe_load(idx_path.read_text(encoding="utf-8"))
    if label == "latest":
        label = index.get("latest", "v0.1")
    return RULES_DIR / label

def load_rules(label: str):
    pack_dir = _resolve_pack_dir(label)
    rules = []
    for pattern in ("*.yml", "*.yaml"):
        for yml in sorted(pack_dir.glob(pattern)):
            doc = yaml.safe_load(yml.read_text(encoding="utf-8"))
            if isinstance(doc, list):
                rules.extend(doc)
            elif isinstance(doc, dict):
                rules.append(doc)
    return rules
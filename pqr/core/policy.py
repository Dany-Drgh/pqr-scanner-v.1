from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import yaml

POLICY_DIR = Path(__file__).resolve().parents[1] / "policy"


@dataclass
class Policy:
    id: str
    version: str
    allowed_families: set[str]
    allowed_draft_families: set[str]
    classical_families: set[str]
    aliases: dict[str, str]
    jwt_classical_prefixes: set[str]
    severity_overrides: dict[str, str]


def load_policy(label: str = "latest") -> Policy:
    index = yaml.safe_load((POLICY_DIR / "index.yaml").read_text(encoding="utf-8"))
    fname = (
        index["packs"][index["latest"]] if label == "latest" else index["packs"][label]
    )
    doc = yaml.safe_load((POLICY_DIR / fname).read_text(encoding="utf-8"))

    meta = doc.get("meta", {})
    sig = doc.get("signatures", {}) or {}
    aliases = dict(doc.get("aliases") or {})

    def norm(name: str) -> str:  # normalize lib-specific name to a family
        return aliases.get(name, name)

    allowed = {norm(x) for x in sig.get("allowed_families", [])}
    allowed_draft = {norm(x) for x in sig.get("allowed_draft_families", [])}
    classical = {norm(x) for x in sig.get("classical_families", [])}

    jwt = doc.get("jwt_alg_families", {}) or {}
    return Policy(
        id=meta.get("id", label),
        version=meta.get("version", ""),
        allowed_families=allowed,
        allowed_draft_families=allowed_draft,
        classical_families=classical,
        aliases=aliases,
        jwt_classical_prefixes=set(jwt.get("classical_prefixes", [])),
        severity_overrides=dict(doc.get("severity_overrides") or {}),
    )

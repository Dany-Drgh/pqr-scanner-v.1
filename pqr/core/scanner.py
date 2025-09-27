from __future__ import annotations
import re, json, shutil
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Dict, Any
from datetime import datetime
from .rules_engine import load_rules

# Add built-in ignores so we never scan our own outputs
DEFAULT_IGNORES = [
    "**/.git/**",
    "**/.hg/**",
    "**/.svn/**",
    "**/__pycache__/**",
    "**/.venv/**",
    "**/venv/**",
    "**/.pqr/**",  # default hidden output/cache
    "**/pqr-scanner-report/**",  # your custom folder (if you keep it)
    "**/report/**",  # legacy name, just in case
]


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    file: str
    line: int
    evidence: str
    fix: str


TEXT_FILE_EXTS = {
    ".py",
    ".yml",
    ".yaml",
    ".json",
    ".env",
    "",
}  # "" catches "Dockerfile"


def _iter_files(root: Path, ignore_globs: Iterable[str]) -> Iterable[Path]:
    all_files = (p for p in root.rglob("*") if p.is_file())
    ignored = set()
    for pat in ignore_globs:
        for m in root.rglob(pat):
            if m.is_file():
                ignored.add(m.resolve())
            else:
                for sub in m.rglob("*"):
                    if sub.is_file():
                        ignored.add(sub.resolve())
    for f in all_files:
        if f.resolve() in ignored:
            continue
        if f.suffix in TEXT_FILE_EXTS or f.name == "Dockerfile":
            yield f


def _match_rule_on_file(rule: Dict[str, Any], path: Path, text: str) -> List[Finding]:
    out: List[Finding] = []
    regexes: List[str] = rule.get("regex", []) or rule.get("regex_any", []) or []
    if not regexes:
        return out
    patterns = [re.compile(rx) for rx in regexes]
    for lineno, line in enumerate(text.splitlines(), start=1):
        for pat in patterns:
            if pat.search(line):
                out.append(
                    Finding(
                        id=rule["id"],
                        title=rule.get("title", rule["id"]),
                        severity=rule.get("severity", "Medium"),
                        file=str(path),
                        line=lineno,
                        evidence=line.strip()[:500],
                        fix=rule.get("fix", ""),
                    )
                )
                break
    return out


def _prepare_outdir(root: Path, outdir: str, timestamped: bool, append: bool) -> Path:
    base = root / outdir
    if timestamped:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        base = base / ts
    if not append:
        shutil.rmtree(base, ignore_errors=True)
    base.mkdir(parents=True, exist_ok=True)
    return base


def write_reports(outdir: Path, findings: List[Finding]) -> None:
    with (outdir / "findings.json").open("w", encoding="utf-8") as f:
        json.dump([asdict(fg) for fg in findings], f, indent=2, ensure_ascii=False)
    with (outdir / "summary.md").open("w", encoding="utf-8") as f:
        if findings:
            f.write(f"# PQR Summary\n\nTotal findings: **{len(findings)}**\n\n")
            for fg in findings[:20]:
                f.write(
                    f"- [{fg.severity}] {fg.id} — {fg.title} ({fg.file}:{fg.line})\n"
                )
            if len(findings) > 20:
                f.write(f"\n…plus {len(findings) - 20} more.\n")
        else:
            f.write("# PQR Summary\n\nNo findings.\n")


def scan_path(
    root: Path,
    ignore_globs: Iterable[str],
    rulepack_label: str = "latest",
    debug: bool = False,
    outdir: str = ".pqr/report",
    timestamped: bool = False,
    append: bool = False,
):
    rules = load_rules(rulepack_label)
    if debug:
        print(f"[pqr] Loaded {len(rules)} rules from pack '{rulepack_label}'")

    all_ignores = list(DEFAULT_IGNORES) + list(ignore_globs or [])
    files = list(_iter_files(root, all_ignores))
    if debug:
        print(f"[pqr] Will scan {len(files)} files under {root}")

    findings: List[Finding] = []
    for fp in files:
        try:
            txt = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for rule in rules:
            findings.extend(_match_rule_on_file(rule, fp, txt))

    out_path = _prepare_outdir(root, outdir, timestamped, append)
    write_reports(out_path, findings)
    if debug:
        print(f"[pqr] Wrote reports to {out_path}")
    return findings

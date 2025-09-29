from __future__ import annotations
import re, json, shutil
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Dict, Any, Set, Tuple
from datetime import datetime
from collections import Counter

from .rules_engine import load_rules
from ..analyzers.python_ast import analyze_python_file

# Add built-in ignores so we never scan our own outputs
DEFAULT_IGNORES = [
    "**/.git/**",
    "**/.hg/**",
    "**/.svn/**",
    "**/__pycache__/**",
    "**/.venv/**",
    "**/venv/**",
    "**/.pqr/**",  # default hidden output/cache
    "**/pqr-scanner-report/**",  # optional custom folder
    "**/report/**",  # legacy name
    "**/node_modules/**",  # in case users have JS bits in repo
    "**/dist/**",
    "**/build/**",
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


def _severity_to_level(sev: str) -> str:
    sev = (sev or "").lower()
    if sev in ("critical", "high"):
        return "error"
    if sev == "medium":
        return "warning"
    return "note"


def write_reports(
    outdir: Path, findings: List[Finding], formats: List[str], meta: dict | None = None
) -> None:
    formats = [f.lower() for f in (formats or ["md", "json", "sarif"])]

    # findings.json (raw items)
    if "json" in formats:
        with (outdir / "findings.json").open("w", encoding="utf-8") as f:
            json.dump([asdict(fg) for fg in findings], f, indent=2, ensure_ascii=False)

        # summary.json (rollups)
        sev = Counter(f.severity for f in findings)
        rid = Counter(f.id for f in findings)
        files = Counter(f.file for f in findings)
        summary = {
            "generatedAt": datetime.utcnow().isoformat() + "Z",
            "total": len(findings),
            "bySeverity": dict(sev),
            "topRules": [{"id": k, "count": v} for k, v in rid.most_common(10)],
            "topFiles": [{"file": k, "count": v} for k, v in files.most_common(10)],
            "meta": meta or {},
        }
        with (outdir / "summary.json").open("w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

    # summary.md (human)
    if "md" in formats:
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

    # pqr.sarif (for code-scanning UIs)
    if "sarif" in formats:
        rules_meta = {}
        for fg in findings:
            rules_meta.setdefault(
                fg.id,
                {
                    "id": fg.id,
                    "name": fg.id,
                    "shortDescription": {"text": fg.title},
                    "defaultConfiguration": {"level": _severity_to_level(fg.severity)},
                },
            )
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "pqr", "rules": list(rules_meta.values())}
                    },
                    "results": [
                        {
                            "ruleId": fg.id,
                            "level": _severity_to_level(fg.severity),
                            "message": {"text": fg.title},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": fg.file},
                                        "region": {"startLine": fg.line},
                                    }
                                }
                            ],
                        }
                        for fg in findings
                    ],
                }
            ],
        }
        with (outdir / "pqr.sarif").open("w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)


def scan_path(
    root: Path,
    ignore_globs: Iterable[str],
    rulepack_label: str = "latest",
    debug: bool = False,
    outdir: str = ".pqr/report",
    timestamped: bool = False,
    append: bool = False,
    formats: List[str] = None,
):
    rules = load_rules(rulepack_label)
    if debug:
        print(f"[pqr] Loaded {len(rules)} rules from pack '{rulepack_label}'")

    all_ignores = list(DEFAULT_IGNORES) + list(ignore_globs or [])
    files = list(_iter_files(root, all_ignores))
    if debug:
        print(f"[pqr] Will scan {len(files)} files under {root}")

    findings: List[Finding] = []
    seen: Set[Tuple[str, str, int]] = set()  # (id, file, line)

    for fp in files:
        try:
            txt = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        # AST checks for Python
        if fp.suffix == ".py":
            for d in analyze_python_file(str(fp), txt):
                key = (d["id"], d["file"], d["line"])
                if key not in seen:
                    findings.append(Finding(**d))
                    seen.add(key)

        # Regex-based rulepack
        for rule in rules:
            for fg in _match_rule_on_file(rule, fp, txt):
                key = (fg.id, fg.file, fg.line)
                if key not in seen:
                    findings.append(fg)
                    seen.add(key)

    meta = {"rulepack": rulepack_label, "outdir": outdir}
    out_path = _prepare_outdir(root, outdir, timestamped, append)
    write_reports(out_path, findings, formats or ["md", "json", "sarif"], meta)
    if debug:
        print(f"[pqr] Wrote reports to {out_path}")
    return findings

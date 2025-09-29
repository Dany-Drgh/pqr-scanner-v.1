from __future__ import annotations

import re
import json
import shutil
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Dict, Any, Set, Tuple, Optional
from datetime import datetime, timezone
from collections import Counter

from .rules_engine import load_rules
from .policy import load_policy, Policy
from ..analyzers.python_ast import analyze_python_file

DEFAULT_IGNORES = [
    "**/.git/**",
    "**/.hg/**",
    "**/.svn/**",
    "**/__pycache__/**",
    "**/.venv/**",
    "**/venv/**",
    "**/.pqr/**",
    "**/pqr-scanner-report/**",
    "**/report/**",
    "**/node_modules/**",
    "**/dist/**",
    "**/build/**",
]
TEXT_FILE_EXTS = {
    ".py",
    ".yml",
    ".yaml",
    ".json",
    ".env",
    ".sh",
    "",  # "" catches "Dockerfile"
}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    file: str
    line: int
    evidence: str
    fix: str


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


def _prepare_outdir(root: Path, outdir: str, timestamped: bool, append: bool) -> Path:
    base = root / outdir
    if timestamped:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        base = base / ts
    if not append:
        shutil.rmtree(base, ignore_errors=True)
    base.mkdir(parents=True, exist_ok=True)
    return base


# ----------------------- Regex rules ---------------------------------------


def _match_regex_rule_on_text(
    rule: Dict[str, Any], path: Path, text: str
) -> List[Finding]:
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


# ----------------------- AST rules -----------------------------------------


def _compile_re(s: str | None) -> Optional[re.Pattern]:
    return re.compile(s) if isinstance(s, str) and s else None


def _call_event_matches(
    pattern: Dict[str, Any], event: Dict[str, Any], ctx: Dict[str, Any], policy: Policy
) -> bool:
    if event.get("type") != "call":
        return False
    callee: str = event.get("callee", "") or ""
    kwargs: Dict[str, Any] = event.get("kwargs", {}) or {}
    evidence: str = event.get("evidence", "") or ""

    want_callee = pattern.get("callee")
    if want_callee and callee != want_callee:
        return False
    callee_rx = _compile_re(pattern.get("callee_regex"))
    if callee_rx and not callee_rx.search(callee):
        return False

    method = pattern.get("method")
    if method and not (callee == method or callee.endswith(f".{method}")):
        return False

    for k, v in (pattern.get("kw_equals") or {}).items():
        if kwargs.get(k) != v:
            return False
    for k, rx in (pattern.get("kw_regex") or {}).items():
        rxp = _compile_re(rx)
        val = str(kwargs.get(k, ""))
        if not rxp or not rxp.search(val):
            return False

    # policy-aware kw checks (e.g., JWT classical prefixes)
    for k, policy_set in (pattern.get("kw_in_policy") or {}).items():
        val = str(kwargs.get(k, "")).upper()
        if policy_set == "jwt_classical_prefixes":
            if not any(
                val.startswith(p) and len(val) >= 4 and val[2:].isdigit()
                for p in policy.jwt_classical_prefixes
            ):
                return False

    ctx_any = pattern.get("when_context_any")
    if isinstance(ctx_any, list) and ctx_any:
        if not any(bool(ctx.get(flag)) for flag in ctx_any):
            return False
    ctx_all = pattern.get("when_context_all")
    if isinstance(ctx_all, list) and ctx_all:
        if not all(bool(ctx.get(flag)) for flag in ctx_all):
            return False

    skip_rx = _compile_re(pattern.get("skip_if_evidence_regex"))
    if skip_rx and skip_rx.search(evidence or ""):
        return False
    return True


def _assign_event_matches(
    pattern: Dict[str, Any], event: Dict[str, Any], policy: Policy
) -> bool:
    if event.get("type") != "assign_pq_signature":
        return False
    alg = str(event.get("alg", ""))
    fam = policy.aliases.get(alg, alg)
    families = pattern.get("families")
    if families == "allowed":
        return any(fam.startswith(x) for x in policy.allowed_families)
    if families == "allowed_or_draft":
        return any(
            fam.startswith(x)
            for x in (policy.allowed_families | policy.allowed_draft_families)
        )
    # regex option
    alg_rx = _compile_re(pattern.get("alg_regex"))
    if alg_rx:
        return bool(alg_rx.search(alg))
    return True  # match any assign if no filter


def _match_ast_rule_on_events(
    rule: Dict[str, Any],
    path: Path,
    events: List[Dict[str, Any]],
    ctx: Dict[str, Any],
    policy: Policy,
) -> List[Finding]:
    ast_block = rule.get("ast")
    if not ast_block:
        return []
    patterns_any: List[Dict[str, Any]] = list(ast_block.get("any") or [])
    out: List[Finding] = []

    for ev in events:
        for pat in patterns_any:
            if "call" in pat and _call_event_matches(pat["call"], ev, ctx, policy):
                out.append(
                    Finding(
                        id=rule["id"],
                        title=rule.get("title", rule["id"]),
                        severity=rule.get("severity", "Medium"),
                        file=str(path),
                        line=int(ev.get("line") or 1),
                        evidence=(ev.get("evidence") or "")[:500],
                        fix=rule.get("fix", ""),
                    )
                )
                break
            if "assign_pq_signature" in pat and _assign_event_matches(
                pat["assign_pq_signature"], ev, policy
            ):
                out.append(
                    Finding(
                        id=rule["id"],
                        title=rule.get("title", rule["id"]),
                        severity=rule.get("severity", "Low"),
                        file=str(path),
                        line=int(ev.get("line") or 1),
                        evidence=(ev.get("evidence") or "")[:500],
                        fix=rule.get("fix", ""),
                    )
                )
                break
    return out


# ----------------------- Reporting -----------------------------------------


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

    if "json" in formats:
        with (outdir / "findings.json").open("w", encoding="utf-8") as f:
            json.dump([asdict(fg) for fg in findings], f, indent=2, ensure_ascii=False)

        sev = Counter(f.severity for f in findings)
        rid = Counter(f.id for f in findings)
        files = Counter(f.file for f in findings)
        summary = {
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "total": len(findings),
            "bySeverity": dict(sev),
            "topRules": [{"id": k, "count": v} for k, v in rid.most_common(10)],
            "topFiles": [{"file": k, "count": v} for k, v in files.most_common(10)],
            "meta": meta or {},
        }
        with (outdir / "summary.json").open("w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

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

    if "sarif" in formats:
        rules_meta: Dict[str, Dict[str, Any]] = {}
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


# ----------------------- Public API ----------------------------------------


def scan_path(
    root: Path,
    ignore_globs: Iterable[str],
    rulepack_label: str = "latest",
    debug: bool = False,
    outdir: str = ".pqr/report",
    timestamped: bool = False,
    append: bool = False,
    formats: List[str] = None,
    policy_label: str = "latest",
):
    rules = load_rules(rulepack_label)
    if debug:
        print(f"[pqr] Loaded {len(rules)} rules from pack '{rulepack_label}'")

    policy = load_policy(policy_label)
    if debug:
        print(f"[pqr] Using policy '{policy.id}' (version {policy.version})")

    regex_rules: List[Dict[str, Any]] = []
    ast_rules: List[Dict[str, Any]] = []
    for r in rules:
        if r.get("ast"):
            ast_rules.append(r)
        if r.get("regex") or r.get("regex_any"):
            regex_rules.append(r)

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

        events: List[Dict[str, Any]] = []
        ctx: Dict[str, Any] = {}
        if fp.suffix == ".py":
            try:
                events, ctx = analyze_python_file(str(fp), txt)
            except Exception as e:
                if debug:
                    print(f"[pqr] AST parse failed for {fp}: {e}")

            for rule in ast_rules:
                for fg in _match_ast_rule_on_events(rule, fp, events, ctx, policy):
                    key = (fg.id, fg.file, fg.line)
                    if key not in seen:
                        findings.append(fg)
                        seen.add(key)

        for rule in regex_rules:
            for fg in _match_regex_rule_on_text(rule, fp, txt):
                key = (fg.id, fg.file, fg.line)
                if key not in seen:
                    findings.append(fg)
                    seen.add(key)

    out_path = _prepare_outdir(root, outdir, timestamped, append)
    meta = {
        "rulepack": rulepack_label,
        "policy": policy.id,
        "policyVersion": policy.version,
        "outdir": outdir,
    }
    write_reports(out_path, findings, formats or ["md", "json", "sarif"], meta)
    if debug:
        print(f"[pqr] Wrote reports to {out_path}")
    return findings

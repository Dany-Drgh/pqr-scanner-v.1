from __future__ import annotations
import argparse
import sys
from pathlib import Path
import json

from .core.scanner import scan_path
from .core.config import load_repo_config


def _sev_ord(s: str) -> int:
    s = (s or "").strip().lower()
    return {
        "info": 1,
        "low": 1,
        "medium": 2,
        "med": 2,
        "high": 3,
        "critical": 4,
    }.get(s, 2)


def _load_baseline(p: Path) -> set[tuple[str, str, int]]:
    if not p.exists():
        return set()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return set()
    out = set()
    for item in data:
        # expect {"id":..., "file":..., "line":...}
        try:
            out.add((str(item["id"]), str(item["file"]), int(item["line"])))
        except Exception:
            pass
    return out


def _write_baseline(p: Path, findings, root: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for f in findings:
        rel = str(Path(f.file).resolve().relative_to(root.resolve()))
        rows.append({"id": f.id, "file": rel, "line": f.line})
    p.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="pqr", description="PQC readiness scanner (Python MVP)"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Scan a repository path")
    p_scan.add_argument("path", type=str, help="Path to the repo root")

    default_ignores = ["tests/**", "**/migrations/**"]
    p_scan.add_argument(
        "--ignore-paths",
        nargs="*",
        default=default_ignores,
        help="Glob patterns to skip",
    )
    p_scan.add_argument(
        "--rulepack", default="latest", help="Rulepack label (e.g., latest, v0.1)"
    )
    p_scan.add_argument(
        "--policy",
        default="latest",
        help="Policy label (see pqr/policy/index.yaml), e.g. latest, nist-stable",
    )
    p_scan.add_argument(
        "--outdir",
        default=".pqr/report",
        help="Report output directory (relative to PATH)",
    )
    p_scan.add_argument(
        "--timestamped",
        action="store_true",
        help="Write to a timestamped subfolder under outdir",
    )
    p_scan.add_argument(
        "--append", action="store_true", help="Do not delete existing outdir content"
    )
    p_scan.add_argument(
        "--formats",
        nargs="*",
        default=["md", "json", "sarif"],
        help="Which report formats to write (any of: md json sarif)",
    )
    p_scan.add_argument(
        "--fail-on-severity",
        choices=["none", "low", "medium", "high", "critical"],
        default="none",
        help="Exit non-zero if any finding meets/exceeds this severity",
    )
    p_scan.add_argument(
        "--use-baseline",
        action="store_true",
        help="Filter out findings present in the baseline file",
    )
    p_scan.add_argument(
        "--update-baseline",
        action="store_true",
        help="Write current findings to the baseline file (after filtering)",
    )
    p_scan.add_argument(
        "--baseline-file",
        default=".pqr/baseline.json",
        help="Baseline file path (relative to PATH)",
    )
    p_scan.add_argument("--debug", action="store_true", help="Print debug info")

    args = parser.parse_args()

    if args.cmd == "scan":
        root = Path(args.path).resolve()

        # Merge repo config AFTER parsing, using repo root.
        cfg = load_repo_config(root)

        def _merge(val, default, key):
            return cfg.get(key, val) if val == default else val

        args.policy = _merge(args.policy, "latest", "policy")
        args.rulepack = _merge(args.rulepack, "latest", "rulepack")
        if args.ignore_paths == default_ignores and cfg.get("ignore-paths"):
            args.ignore_paths = cfg["ignore-paths"]
        if args.formats == ["md", "json", "sarif"] and cfg.get("formats"):
            args.formats = cfg["formats"]
        if args.fail_on_severity == "none" and cfg.get("fail-on-severity"):
            args.fail_on_severity = cfg["fail-on-severity"]
        # baseline config block
        bcfg = cfg.get("baseline") or {}
        if args.baseline_file == ".pqr/baseline.json" and bcfg.get("file"):
            args.baseline_file = bcfg["file"]
        if not args.use_baseline and bool(bcfg.get("use")):
            args.use_baseline = True
        if not args.update_baseline and bool(bcfg.get("update")):
            args.update_baseline = True

        baseline_set = set()
        baseline_path = root / args.baseline_file
        if args.use_baseline:
            baseline_set = _load_baseline(baseline_path)

        findings = scan_path(
            root,
            ignore_globs=args.ignore_paths,
            rulepack_label=args.rulepack,
            policy_label=args.policy,
            debug=args.debug,
            outdir=args.outdir,
            timestamped=args.timestamped,
            append=args.append,
            formats=args.formats,
            baseline=baseline_set or None,  # new param in scanner
        )

        print(f"Scanned: {root}")
        print(f"Findings: {len(findings)} (see {args.outdir})")

        if args.update_baseline:
            _write_baseline(baseline_path, findings, root)
            print(f"Baseline written to {baseline_path}")

        # Gate on severity
        if args.fail_on_severity != "none":
            threshold = _sev_ord(args.fail_on_severity)
            should_fail = any(_sev_ord(f.severity) >= threshold for f in findings)
            return 1 if should_fail else 0

        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())

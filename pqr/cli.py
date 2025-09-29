from __future__ import annotations
import argparse
import sys
from pathlib import Path

from .core.scanner import scan_path


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="pqr", description="PQC readiness scanner (Python MVP)"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Scan a repository path")
    p_scan.add_argument("path", type=str, help="Path to the repo root")
    p_scan.add_argument(
        "--ignore-paths",
        nargs="*",
        default=["tests/**", "**/migrations/**"],
        help="Glob patterns to skip",
    )
    p_scan.add_argument(
        "--rulepack", default="latest", help="Rulepack label (e.g., latest, v0.1)"
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
    p_scan.add_argument("--debug", action="store_true", help="Print debug info")

    p_scan.add_argument(
        "--policy",
        default="latest",
        help="Policy label to use (see pqr/policy/index.yaml, e.g. latest, nist-stable, nist-draft)",
    )
    args = parser.parse_args()

    if args.cmd == "scan":
        root = Path(args.path).resolve()
        findings = scan_path(
            root,
            ignore_globs=args.ignore_paths,
            rulepack_label=args.rulepack,
            debug=args.debug,
            outdir=args.outdir,
            timestamped=args.timestamped,
            append=args.append,
            formats=args.formats,
            policy_label=args.policy,
        )
        print(f"Scanned: {root}")
        print(f"Findings: {len(findings)} (see {args.outdir})")
        # Optional: keep your existing --fail-on-severity logic if you added it earlier.
        return 1 if findings else 0

    return 0


if __name__ == "__main__":
    sys.exit(main())

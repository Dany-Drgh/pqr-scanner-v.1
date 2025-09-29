from pathlib import Path
import json
from pqr.core.scanner import scan_path


def test_minimal_repo_emits_expected_findings():
    repo_root = Path(__file__).resolve().parents[2]
    target = repo_root / "examples" / "minimal-python"

    findings = scan_path(
        root=target,
        ignore_globs=[],  # built-in ignores still apply
        rulepack_label="latest",
        policy_label="nist-stable",
        debug=False,
        outdir=".pqr/report",
        timestamped=False,
        append=False,
        formats=["md", "json", "sarif"],
    )

    ids = {f.id for f in findings}
    expected = {
        "PY-REQ-NOVERIFY",
        "PY-JWT-CLASSICAL-SIG",
        "PY-HASH-MD5-SHA1",
        "PY-AES-ECB",
        "PY-SSL-OLD-PROTO",
        "TOOL-OPENSSL-GENRSA",
        "TOOL-OPENSSL-SIGN",
    }
    missing = expected - ids
    assert not missing, f"Missing findings: {missing}; got {ids}"

    outdir = target / ".pqr" / "report"
    assert (outdir / "findings.json").exists()
    assert (outdir / "summary.json").exists()
    assert (outdir / "pqr.sarif").exists()

    # second run should not snowball
    f2 = scan_path(
        root=target,
        ignore_globs=[],
        rulepack_label="latest",
        policy_label="nist-stable",
        debug=False,
        outdir=".pqr/report",
        timestamped=False,
        append=False,
        formats=["json"],
    )
    assert len(f2) == len(findings)

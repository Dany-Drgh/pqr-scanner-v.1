from pathlib import Path
import shutil
import pytest
from pqr.core.scanner import scan_path

CASES = []
root = Path(__file__).resolve().parents[2] / "tests" / "rules"
if root.exists():
    for rid_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        rid = rid_dir.name
        for kind in (
            "should_match.py",
            "should_not_match.py",
            "should_match.sh",
            "should_not_match.sh",
        ):
            f = rid_dir / kind
            if f.exists():
                CASES.append((rid, kind, f))


@pytest.mark.parametrize("rid,kind,src", CASES)
def test_rule_fixture(rid, kind, src, tmp_path: Path):
    dst = tmp_path / src.name
    shutil.copy(src, dst)

    findings = scan_path(
        root=tmp_path,
        ignore_globs=[],
        rulepack_label="latest",
        policy_label="nist-stable",
        debug=False,
        outdir=".pqr/report",
        timestamped=False,
        append=False,
        formats=["json"],
    )
    ids = {f.id for f in findings}
    if "should_match" in kind:
        assert rid in ids, f"{rid} didn't match {src}"
    else:
        assert rid not in ids, f"{rid} matched unexpectedly on {src}"

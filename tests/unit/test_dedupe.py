from pathlib import Path
from pqr.core.scanner import scan_path

PY = """\
import requests, jwt
def f():
    requests.get("https://x", verify=False)
    jwt.encode({"a":1}, "k", algorithm="RS256")
"""


def test_dedupe_same_line(tmp_path: Path):
    demo = tmp_path / "demo.py"
    demo.write_text(PY, encoding="utf-8")

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

    # Should include both rules, but NOT duplicates of the same rule/line
    ids = [f.id for f in findings]
    assert "PY-REQ-NOVERIFY" in ids
    assert "PY-JWT-CLASSICAL-SIG" in ids
    # ensure unique (id, file, line)
    seen = set()
    for f in findings:
        key = (f.id, f.file, f.line)
        assert key not in seen, f"duplicate finding {key}"
        seen.add(key)

from pathlib import Path
from pqr.analyzers.python_ast import analyze_python_file


def test_ast_emits_expected_events():
    repo = Path(__file__).resolve().parents[2]
    app = (repo / "examples/minimal-python/app.py").read_text(encoding="utf-8")
    events, ctx = analyze_python_file(str(repo / "examples/minimal-python/app.py"), app)

    # jwt.encode w/ algorithm
    encalls = [
        e for e in events if e["type"] == "call" and e.get("callee") == "jwt.encode"
    ]
    assert encalls, "no jwt.encode call event"
    assert any(e["kwargs"].get("algorithm") == "RS256" for e in encalls)

    # requests.get with verify=False
    reqcalls = [
        e for e in events if e["type"] == "call" and e.get("callee") == "requests.get"
    ]
    assert any(e["kwargs"].get("verify") is False for e in reqcalls)

    # context exists
    assert isinstance(ctx, dict)

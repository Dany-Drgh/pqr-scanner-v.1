import re
from pqr.core.rules_engine import load_rules


def test_rules_load_and_compile():
    rules = load_rules("latest")
    assert rules, "no rules loaded"
    seen = set()
    for r in rules:
        rid = r["id"]
        assert rid not in seen, f"duplicate rule id {rid}"
        seen.add(rid)
        # basic shape
        assert "title" in r and "severity" in r
        has_regex = bool(r.get("regex") or r.get("regex_any"))
        has_ast = "ast" in r
        assert has_regex or has_ast, f"{rid} has neither regex nor ast"
        # regexes compile
        for pat in r.get("regex", []) + r.get("regex_any", []):
            re.compile(pat)

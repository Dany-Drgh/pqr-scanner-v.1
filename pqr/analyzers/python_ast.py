from __future__ import annotations
import ast
from typing import List, Dict, Set

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "request"}


def _source_line(text: str, lineno: int) -> str:
    try:
        return text.splitlines()[lineno - 1].strip()[:500]
    except Exception:
        return ""


def analyze_python_file(path: str, text: str) -> List[Dict]:
    """
    Returns a list of finding dicts with keys:
    id, title, severity, file, line, evidence, fix
    """
    findings: List[Dict] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return findings

    # Track aliases: import requests as req; import jwt as pyjwt; from requests import get
    request_aliases: Set[str] = set()
    request_funcs: Set[str] = set()
    jwt_aliases: Set[str] = set()
    jwt_funcs: Set[str] = set()

    class ImportTracker(ast.NodeVisitor):
        def visit_Import(self, node: ast.Import) -> None:
            for alias in node.names:
                if alias.name == "requests":
                    request_aliases.add(alias.asname or alias.name)
                if alias.name == "jwt":
                    jwt_aliases.add(alias.asname or alias.name)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            if node.module == "requests":
                for alias in node.names:
                    request_funcs.add(alias.asname or alias.name)
            if node.module == "jwt":
                for alias in node.names:
                    jwt_funcs.add(alias.asname or alias.name)

    class CallScanner(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            # Determine callee kind and name
            callee_name = None
            # e.g., requests.get(...)
            if isinstance(node.func, ast.Attribute) and isinstance(
                node.func.value, ast.Name
            ):
                base = node.func.value.id
                attr = node.func.attr
                if base in request_aliases and attr in HTTP_METHODS:
                    # requests.<method>(..., verify=False)
                    for kw in node.keywords or []:
                        if (
                            kw.arg == "verify"
                            and isinstance(kw.value, ast.Constant)
                            and kw.value.value is False
                        ):
                            findings.append(
                                {
                                    "id": "PY-REQ-NOVERIFY",
                                    "title": "TLS verification disabled in requests call",
                                    "severity": "Medium",
                                    "file": path,
                                    "line": node.lineno,
                                    "evidence": _source_line(text, node.lineno),
                                    "fix": "Avoid verify=False; use a valid CA bundle or careful pinning.",
                                }
                            )
                            break

                if base in jwt_aliases and attr == "encode":
                    # jwt.encode(..., algorithm="RS256"/"ES256")
                    for kw in node.keywords or []:
                        if (
                            kw.arg == "algorithm"
                            and isinstance(kw.value, ast.Constant)
                            and isinstance(kw.value.value, str)
                        ):
                            alg = kw.value.value
                            if (
                                len(alg) >= 4
                                and (alg.startswith("RS") or alg.startswith("ES"))
                                and alg[2:].isdigit()
                            ):
                                findings.append(
                                    {
                                        "id": "PY-JWT-RS-ES",
                                        "title": "JWT signed with RS*/ES* (classical)",
                                        "severity": "High",
                                        "file": path,
                                        "line": node.lineno,
                                        "evidence": _source_line(text, node.lineno),
                                        "fix": "Plan a migration to PQ-capable tokens or reduce token lifetimes during transition.",
                                    }
                                )
                            break

            # e.g., get(..., verify=False) if `from requests import get`
            if isinstance(node.func, ast.Name) and node.func.id in request_funcs:
                for kw in node.keywords or []:
                    if (
                        kw.arg == "verify"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is False
                    ):
                        findings.append(
                            {
                                "id": "PY-REQ-NOVERIFY",
                                "title": "TLS verification disabled in requests call",
                                "severity": "Medium",
                                "file": path,
                                "line": node.lineno,
                                "evidence": _source_line(text, node.lineno),
                                "fix": "Avoid verify=False; use a valid CA bundle or careful pinning.",
                            }
                        )
                        break

            # e.g., encode(..., algorithm="RS256") if `from jwt import encode`
            if isinstance(node.func, ast.Name) and node.func.id in jwt_funcs:
                for kw in node.keywords or []:
                    if (
                        kw.arg == "algorithm"
                        and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, str)
                    ):
                        alg = kw.value.value
                        if (
                            len(alg) >= 4
                            and (alg.startswith("RS") or alg.startswith("ES"))
                            and alg[2:].isdigit()
                        ):
                            findings.append(
                                {
                                    "id": "PY-JWT-RS-ES",
                                    "title": "JWT signed with RS*/ES* (classical)",
                                    "severity": "High",
                                    "file": path,
                                    "line": node.lineno,
                                    "evidence": _source_line(text, node.lineno),
                                    "fix": "Plan a migration to PQ-capable tokens or reduce token lifetimes during transition.",
                                }
                            )
                        break

            self.generic_visit(node)

    ImportTracker().visit(tree)
    CallScanner().visit(tree)
    return findings

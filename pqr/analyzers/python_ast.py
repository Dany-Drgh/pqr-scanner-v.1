from __future__ import annotations

import ast
from typing import Any, Dict, List, Set, Tuple

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "request"}


def _line(text: str, lineno: int) -> str:
    try:
        return text.splitlines()[lineno - 1].strip()[:500]
    except Exception:
        return ""


def analyze_python_file(
    path: str, text: str
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Parse Python and emit normalized AST 'events' + a small 'ctx' blob.
    No policy or rule knowledge here.

    Returns:
      (events, ctx)

    Event shapes (examples):
      {"type":"import", "module":"jwt", "names":["encode"], "line": 1}
      {"type":"call", "callee":"jwt.encode", "kwargs":{"algorithm":"RS256"}, "line": 10, "evidence":"..."}
      {"type":"call", "callee":"requests.get", "kwargs":{"verify": False}, "line": 5, "evidence":"..."}
      {"type":"assign_pq_signature", "alg":"ML-DSA-65", "target":"sig", "line": 7, "evidence":"..."}
    Ctx:
      {
        "classical_asym_present": bool,
        "pynacl_sign_present": bool,
        "pq_sig_vars": set[str],             # variables bound to oqs.Signature(...)
        "aliases": {"oqs": "oqs", ...},      # basic alias map for requests/jwt/oqs
      }
    """
    events: List[Dict[str, Any]] = []
    ctx: Dict[str, Any] = {
        "classical_asym_present": False,
        "pynacl_sign_present": False,
        "pq_sig_vars": set(),
        "aliases": {},
    }

    try:
        tree = ast.parse(text)
    except SyntaxError:
        return events, ctx

    request_aliases: Set[str] = set()
    request_funcs: Set[str] = set()
    jwt_aliases: Set[str] = set()
    jwt_funcs: Set[str] = set()
    oqs_aliases: Set[str] = set()
    signature_ctor_names: Set[str] = set()

    class ImportTracker(ast.NodeVisitor):
        def visit_Import(self, node: ast.Import) -> None:
            for alias in node.names:
                name = alias.name
                asname = alias.asname or alias.name
                if name == "requests":
                    request_aliases.add(asname)
                    ctx["aliases"]["requests"] = asname
                    events.append(
                        {
                            "type": "import",
                            "module": "requests",
                            "names": [],
                            "line": getattr(node, "lineno", 0),
                        }
                    )
                elif name == "jwt":
                    jwt_aliases.add(asname)
                    ctx["aliases"]["jwt"] = asname
                    events.append(
                        {
                            "type": "import",
                            "module": "jwt",
                            "names": [],
                            "line": getattr(node, "lineno", 0),
                        }
                    )
                elif name == "oqs":
                    oqs_aliases.add(asname)
                    ctx["aliases"]["oqs"] = asname
                    events.append(
                        {
                            "type": "import",
                            "module": "oqs",
                            "names": [],
                            "line": getattr(node, "lineno", 0),
                        }
                    )
                elif name == "nacl.signing":
                    ctx["pynacl_sign_present"] = True
                    events.append(
                        {
                            "type": "import",
                            "module": "nacl.signing",
                            "names": [],
                            "line": getattr(node, "lineno", 0),
                        }
                    )

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            mod = node.module or ""
            names = [a.asname or a.name for a in node.names]
            if mod == "requests":
                for n in names:
                    request_funcs.add(n)
                events.append(
                    {
                        "type": "import",
                        "module": mod,
                        "names": names,
                        "line": getattr(node, "lineno", 0),
                    }
                )
            elif mod == "jwt":
                for n in names:
                    jwt_funcs.add(n)
                events.append(
                    {
                        "type": "import",
                        "module": mod,
                        "names": names,
                        "line": getattr(node, "lineno", 0),
                    }
                )
            elif mod.startswith("cryptography.hazmat.primitives.asymmetric"):
                ctx["classical_asym_present"] = True
                events.append(
                    {
                        "type": "import",
                        "module": mod,
                        "names": names,
                        "line": getattr(node, "lineno", 0),
                    }
                )
            elif mod == "nacl.signing":
                ctx["pynacl_sign_present"] = True
                events.append(
                    {
                        "type": "import",
                        "module": mod,
                        "names": names,
                        "line": getattr(node, "lineno", 0),
                    }
                )
            elif mod == "oqs":
                for alias in node.names:
                    if (alias.asname or alias.name) == "Signature":
                        signature_ctor_names.add("Signature")
                events.append(
                    {
                        "type": "import",
                        "module": mod,
                        "names": names,
                        "line": getattr(node, "lineno", 0),
                    }
                )

    ImportTracker().visit(tree)

    # Assign tracking: sig = oqs.Signature("ALG")
    class AssignTracker(ast.NodeVisitor):
        def visit_Assign(self, node: ast.Assign) -> None:
            call = node.value
            if not isinstance(call, ast.Call):
                return

            # oqs.Signature("ALG") with oqs alias
            if isinstance(call.func, ast.Attribute) and isinstance(
                call.func.value, ast.Name
            ):
                if call.func.attr == "Signature" and call.func.value.id in oqs_aliases:
                    args = call.args or []
                    if (
                        args
                        and isinstance(args[0], ast.Constant)
                        and isinstance(args[0].value, str)
                    ):
                        alg = args[0].value
                        for t in node.targets:
                            if isinstance(t, ast.Name):
                                ctx["pq_sig_vars"].add(t.id)
                                events.append(
                                    {
                                        "type": "assign_pq_signature",
                                        "alg": alg,
                                        "target": t.id,
                                        "line": node.lineno,
                                        "evidence": _line(text, node.lineno),
                                    }
                                )

            # Direct Signature(...) if imported directly
            if isinstance(call.func, ast.Name) and call.func.id in {
                "Signature",
                *signature_ctor_names,
            }:
                args = call.args or []
                if (
                    args
                    and isinstance(args[0], ast.Constant)
                    and isinstance(args[0].value, str)
                ):
                    alg = args[0].value
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            ctx["pq_sig_vars"].add(t.id)
                            events.append(
                                {
                                    "type": "assign_pq_signature",
                                    "alg": alg,
                                    "target": t.id,
                                    "line": node.lineno,
                                    "evidence": _line(text, node.lineno),
                                }
                            )

    AssignTracker().visit(tree)

    # Calls scanning
    class CallScanner(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            # Build a callee string like "requests.get" or "jwt.encode" or plain "encode"
            callee = None
            if isinstance(node.func, ast.Attribute):
                base = node.func.value
                if isinstance(base, ast.Name):
                    callee = f"{base.id}.{node.func.attr}"
                elif isinstance(base, ast.Call):
                    # e.g., oqs.Signature("ALG").sign  -> callee stays ".sign" w/out base name
                    callee = node.func.attr
                else:
                    callee = node.func.attr
            elif isinstance(node.func, ast.Name):
                callee = node.func.id

            # Extract literal kwargs (constants only)
            kwargs: Dict[str, Any] = {}
            for kw in node.keywords or []:
                if not isinstance(kw, ast.keyword) or kw.arg is None:
                    continue
                v = kw.value
                if isinstance(v, ast.Constant):
                    kwargs[kw.arg] = v.value

            events.append(
                {
                    "type": "call",
                    "callee": callee or "",
                    "kwargs": kwargs,
                    "line": getattr(node, "lineno", 0),
                    "evidence": _line(text, getattr(node, "lineno", 0)),
                }
            )

            self.generic_visit(node)

    CallScanner().visit(tree)
    return events, ctx

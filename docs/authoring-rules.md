# Authoring rules

PQR supports two kinds of rules:

1. **Regex rules** — line-based matches with file/line evidence.
2. **AST rules (Python)** — event-driven matches emitted by the analyzer.

All rules live in `pqr/rules/<pack>/...` and are loaded via
`pqr/rules/index.yaml` (`latest: v0.1`).

## Rule schema (common keys)

```yaml
- id: PY-REQ-NOVERIFY            # unique across pack
  title: "Short, actionable title"
  description: "Optional; one sentence of context."
  severity: High|Medium|Low|Info
  regex_any:                      # OR
    - "pattern"
  ast:                            # OR
    any:
      - call:
          callee: "jwt.encode"
          kw_equals: { verify: false }
  fix: "Concrete, minimal remediation."
  references:
    - "https://example.com/spec"
```

## Regex tips

Keep lines ≤80 chars; use folded scalars:
```yaml
regex_any:
  - >-
    \bopenssl\s+(dgst|pkeyutl)\b.*-sign\b
```

- Escape backslashes properly (\\. inside YAML).
-Prefer conservative patterns to avoid false positives.

## AST (Python) DSL

Events emitted by the analyzer (simplified):

- `{"type":"call","callee":"jwt.encode","kwargs":{"algorithm":"RS256"},"line":10,"evidence":"..."}`
- `{"type":"assign_pq_signature","alg":"ML-DSA-65","target":"sig","line":7,"evidence":"..."}`

Supported matchers (inside `ast: any:`):
```yaml
- call:
    callee: "jwt.encode"                      # exact
    callee_regex: "^requests\\.(get|post)$"   # regex
    method: "sign"                            # matches '*.sign'
    kw_equals: { verify: false }
    kw_regex: { algorithm: "^(RS|ES|PS)\\d{3}$" }
    kw_in_policy: { algorithm: "jwt_classical_prefixes" }
    when_context_any: [ "classical_asym_present" ]
    skip_if_evidence_regex: "oqs\\.Signature\\("
- assign_pq_signature:
    families: "allowed" | "allowed_or_draft"  # policy driven
    # or alg_regex: "ML-DSA-.*"
```

## Testing your rule

Add fixtures under `tests/rules/<RULE_ID>/`:

```bash
tests/rules/PY-FOO/should_match.py
tests/rules/PY-FOO/should_not_match.py
```
Our parametrized test will auto-discover and assert them.

Run:

```bash
pytest -q
```

## Severity guidance

- High: cryptographic choice that risks long-term confidentiality/ authenticity (e.g., classical sig for long-lived artifacts, AES-ECB).
- Medium: risky configs (TLSv1/1.1), weak hashes (MD5/SHA1).
- Low/Info: positive signals (e.g., OQS usage), heads-up items.

## Policy coupling

If a rule depends on standards, prefer policy-driven checks:

- Use `kw_in_policy` for JWT classical prefixes

- Use `assign_pq_signature.families: allowed_or_draft` for PQ algs

This keeps rules stable when policies evolve.

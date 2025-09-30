# CONTRIBUTING.md (new)

## Contributing to PQR

Thanks for helping! A quick checklist:

1. **Fork & branch**
2. **Dev install:** `pip install -e ".[test]"` and `pre-commit install`
3. **Run hooks/tests:** `pre-commit run --all-files` and `pytest -q`
4. **Add rules?** See `docs/authoring-rules.md`
5. **Open a PR** with a clear title and motivation

## Code style / tooling

- Python ≥ 3.11
- Black, Ruff, Yamllint via pre-commit
- Tests with pytest (keep them fast and isolated)

## Versioning

We track versions separately:
- **Engine** (code)
- **Rulepacks** (`pqr/rules/…`)
- **Policies** (`pqr/policy/…`)

Rulepack changes should bump the rulepack label (e.g., `v0.2`) and update
`pqr/rules/index.yaml`. Policy changes update the policy file and index.

## DCO / Sign-off

Please include a “Signed-off-by” line in your commits if your org requires it.

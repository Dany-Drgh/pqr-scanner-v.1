# PQR — Post-Quantum Readiness Scanner (Python MVP)

PQR scans codebases to surface crypto choices that are risky in a
post-quantum world, plus general crypto hygiene issues.
**Status:** Python-focused MVP with rulepacks + policies.

## Quickstart

```bash
pip install -e .            # dev install
pqr scan . --policy nist-stable
```

Outputs (by default): `.pqr/report/{summary.md, findings.json, pqr.sarif}`

## Usage
```bash
pqr scan <path> [flags]

--rulepack <label>         # rules index.yaml maps 'latest' -> v0.1
--policy <label>           # policy/index.yaml (e.g., nist-stable)
--ignore-paths a b c      # extra globs on top of built-ins
--outdir <dir>            # default: .pqr/report
--timestamped             # write into .pqr/report/<YYYYMMDD-HHMMSS>/
--append                  # don't clear outdir first
--formats md json sarif   # any subset
--fail-on-severity <lvl>  # none|low|medium|high|critical
--use-baseline            # suppress items listed in baseline file
--update-baseline         # write current findings to baseline
--baseline-file <path>    # default: .pqr/baseline.json
--debug
```

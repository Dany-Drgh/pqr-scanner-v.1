# PQR (Post-Quantum Readiness) — Python MVP

## Quickstart
```bash
python -m venv .venv && source .venv/bin/activate  # on Windows: .venv\Scripts\activate
pip install -e .
pqr scan .
```

# Outputs
By default reports are written to `.pqr/report/` and overwritten on each run.
Use `--timestamped` to write to `.pqr/report/<YYYYMMDD-HHMMSS>/`.
Use `--outdir pqr-scanner-report` if you prefer a non-hidden folder.
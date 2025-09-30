# Configuration

## Repo defaults: `.pqrrc.yaml`

```yaml
---
policy: nist-stable
rulepack: latest
ignore-paths:
  - "tests/**"
formats: ["md","json","sarif"]
fail-on-severity: none
baseline:
  file: ".pqr/baseline.json"
  use: false
  update: false
```

- CLI flags always take precedence over `.pqrrc.yaml`.

## Suppressions

Line: `# pqr: ignore=RULE_ID[,RULE2]` (use * to ignore all on that line)

File: `# pqr: ignore-file` near top of file

## Baseline

- `--update-baseline` writes the current findings
- `--use-baseline` filters future runs by {id,file,line} entries
- Default path is `.pqr/baseline.json` (configurable)

## Outputs

- `summary.md`: human summary
- `findings.json`: full detail (for dashboards)
- `pqr.sarif`: loadable in code scanning UIs

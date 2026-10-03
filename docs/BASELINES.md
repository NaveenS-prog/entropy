# Baselines (`.entropy-baseline.json`)

Entropy baselines enable incremental adoption of architectural and security debt standards on large existing codebases without forcing developers to immediately remediate legacy findings.

---

## 1. Overview & Principles

- **Metadata-Only Storage:** Baseline files store only fingerprints, rule IDs, file locations, line ranges, and aggregate scores. Source code snippets and repository contents are NEVER saved into `.entropy-baseline.json`.
- **Zero Double-Scanning:** Entropy performs exactly one discovery, parsing, analysis, and scoring pass during execution, reusing scan data for both baseline creation and differential evaluation.
- **Auditable Lineage:** The baseline records `commit_sha`, `is_dirty`, `config_hash`, `scan_id`, and `created_at` to provide a complete audit trail.

---

## 2. Baseline Lifecycle Commands

### Create a Baseline
Scan the repository and capture all current findings into `.entropy-baseline.json`:
```bash
entropy baseline create [path]
```
If `.entropy-baseline.json` already exists, Entropy prompts for confirmation or requires `--force`.

### Inspect a Baseline
Print metadata, snapshot statistics, and finding count of the current baseline:
```bash
entropy baseline show [path]
```

### Update a Baseline
Rescan the repository and overwrite the baseline with the current state:
```bash
entropy baseline update [path]
```

### Clear a Baseline
Remove the baseline file. Requires `--yes` flag to prevent accidental removal:
```bash
entropy baseline clear [path] --yes
```

---

## 3. Differential Policy Evaluation

When a baseline is present and `baseline.track_new_only: true` is configured in `.entropy.yml` (or `--baseline` is specified):
- `entropy check` compares the current scan against the baseline.
- Findings are partitioned into `NEW`, `RESOLVED`, and `PERSISTENT`.
- Policy checks (such as blocking on critical severity findings or blocking on score degradation) are evaluated against the delta (new findings and score change relative to the baseline).
- Output reports summary stats:
```
Baseline Comparison:
  - 4 persistent
  + 0 new
  - 2 resolved
```

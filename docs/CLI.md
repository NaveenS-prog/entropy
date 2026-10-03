# Entropy Developer CLI Documentation

Entropy provides a deterministic static-analysis and architectural/security debt CLI for developers and CI/CD pipelines.

---

## 1. Installation

Entropy is packaged as a standard Python package. To install it locally in development mode:

```bash
cd backend
pip install -e .
```

This registers the `entropy` command-line executable. Alternatively, you can invoke the module directly:

```bash
python -m app.cli.main --help
```

---

## 2. Command Overview

Entropy CLI commands are structured as follows:

```
entropy
├── init [path]               Initialize .entropy.yml configuration file
├── config
│   └── validate [path]       Validate .entropy.yml schema and security rules
├── baseline
│   ├── create [path]         Create .entropy-baseline.json from current scan
│   ├── show [path]           Display baseline metadata and findings summary
│   ├── update [path]         Update existing baseline with current scan
│   └── clear [path]          Delete baseline file (requires --yes)
├── scan [path]               Scan repository, compute findings and debt score
├── check [path]              Scan repository and evaluate against policy (primary CI gate)
├── findings [path]           Inspect granular findings with filters (--new, --suppressed)
├── compare <base> <head>     Compare debt between two repository paths or scans
├── explain <finding-id>      Advisory AI explanation and remediation for a finding
├── version                   Display Entropy engine version
└── policy
    ├── validate <file>       Validate policy configuration file
    └── evaluate              Evaluate policy against scans or comparisons
```

---

## 3. Global Options

- `--format [text|json|sarif]`: Output format for `scan`, `check`, and `findings` (default: `text`).
- `--quiet, -q`: Suppress informational output, displaying only results or errors.
- `--verbose, -v`: Display diagnostic progress messages to stderr.
- `--no-color`: Disable ANSI color escapes (useful for non-interactive loggers).
- `--version`: Display version (`entropy 0.1.0`) and exit.

---

## 4. `entropy init`

Initializes a starter `.entropy.yml` project configuration in the target directory (default: `.`). Fails with exit code 2 if a configuration file already exists.

### Usage
```bash
entropy init
entropy init /path/to/project
```

---

## 5. `entropy config validate`

Strictly validates an existing `.entropy.yml` configuration against the schema, verifying version compatibility, valid rule IDs, and prohibiting path traversal attempts.

### Usage
```bash
entropy config validate
entropy config validate /path/to/project
```

---

## 6. `entropy baseline`

Manages baseline snapshots (`.entropy-baseline.json`) for incremental debt gating. Baselines contain only metadata and fingerprints—no source code is stored.

### Subcommands
```bash
# Create baseline from current repository state
entropy baseline create [path]

# Show baseline metadata, scan ID, score, and finding counts
entropy baseline show [path]

# Update baseline to match current repository state
entropy baseline update [path]

# Clear/delete baseline file (requires --yes)
entropy baseline clear [path] --yes
```

---

## 7. `entropy scan`

Scans a repository path (default: `.`), discovers scannable files, runs registered AST analyzers across supported languages (Python, JavaScript, TypeScript), and computes the aggregate Entropy Debt score.

### Usage
```bash
entropy scan .
entropy scan /path/to/project --format json
entropy scan . --format sarif
```

### Example Human Output
```
Entropy Scan
────────────────────────────
Repository: /home/naveen/Entropy

Files discovered: 309
Files analyzed: 276
Lines of code: 237228
Findings: 221

Entropy Score: 18 / 100
Band: Very Low

Categories:

  Error Handling             47.7
  Authentication             13.5
  Authorization              11.3
  Input Validation            8.9
  Logging & Secrets          23.3
  Code Duplication           23.1
  Architecture                2.9
```

---

## 8. `entropy check` (Primary CI Gate)

Runs a single scan pass, computes the debt score, and evaluates the results against a policy. If `.entropy.yml` or a baseline is present, it evaluates policies against baseline deltas.

### Usage
```bash
entropy check .
entropy check . --policy .entropy-policy.yaml
entropy check . --baseline .entropy-baseline.json
entropy check . --fail-on-warn
entropy check . --format json
```

### Exit Codes
- `0`: PASS (or WARN when `--fail-on-warn` is omitted)
- `1`: POLICY FAIL (or WARN when `--fail-on-warn` is passed)
- `2`: CONFIGURATION / ARGUMENT ERROR (invalid policy, malformed flags, schema violations)
- `3`: ANALYSIS / SYSTEM ERROR (path not found, invalid repository)

---

## 9. `entropy findings`

Lists individual findings discovered during analysis with optional filtering.

### Usage
```bash
# View all findings
entropy findings .

# Filter only new findings relative to baseline
entropy findings . --new

# Filter only suppressed findings and review reasons
entropy findings . --suppressed

# Filter by severity
entropy findings . --severity high

# Filter by specific rule ID
entropy findings . --rule ENT-ERR-001

# Filter by category
entropy findings . --category error_handling

# Output as JSON or SARIF
entropy findings . --severity critical --format json
```

---

## 10. `entropy compare`

Compares two repository scans or directories to evaluate architectural debt trends.

### Usage
```bash
# Compare two local directories
entropy compare /path/to/base_repo /path/to/head_repo

# Compare by scan IDs
entropy compare <base_scan_id> <head_scan_id>
```

### Example Output
```
Entropy Comparison
────────────────────────────
Base:  13
Head:  17
Delta: +4

New:        3
Resolved:   1
Persistent: 41

Category Deltas:
  Error Handling               +3.2
  Authentication                0.0
  ...
```

---

## 11. `entropy explain`

Provides advisory AI explanation and remediation for a specific finding.

### Usage
```bash
entropy explain <finding-id>
```

### Guarantees
- **Strictly Advisory:** AI output never alters deterministic findings, severity, confidence, or the entropy debt score.
- **Graceful Fallback:** If `AI_ENABLED=false` or the AI provider is unavailable, Entropy prints a notice without raising a fatal error.

---

## 12. `entropy policy`

Manages and evaluates standalone policy files.

### Validate Policy
```bash
entropy policy validate .entropy-policy.yaml
```

### Evaluate Policy
```bash
entropy policy evaluate --policy .entropy-policy.yaml --scan-file scan.json
entropy policy evaluate --policy .entropy-policy.yaml --comparison-file comp.json --fail-on-warn
```

---

## 13. CI/CD Integration Examples

### GitHub Actions
```yaml
name: Entropy Architectural Gate

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  entropy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Entropy
        run: pip install -e backend

      - name: Run Entropy Policy Check
        run: entropy check . --fail-on-warn

      - name: Generate SARIF Report
        if: always()
        run: entropy scan . --format sarif > entropy-results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: entropy-results.sarif
```

---

## 14. Security Guarantees & Non-Execution Invariants

Entropy enforces strict zero-code-execution during all analysis:
1. **No Code Execution:** Repository source files are parsed via `ast.parse` and syntactic lexers; no files are imported, eval'd, or executed.
2. **No Dependency Tooling:** Entropy does not run `npm`, `pip`, `setup.py`, or build scripts.
3. **Safe Git Queries:** Only read-only metadata commands (`git rev-parse HEAD`, etc.) are executed without shell interpolation (`shell=False`).
4. **Tested Invariant:** Verified via malicious canary test (`ENTROPY_CLI_HACKED.txt` is never created).

# Phase 13 — Policy Engine & CI/CD Enforcement

## 1. Architectural Overview

Entropy's **Policy Engine** evaluates static analysis and scan comparison results against declarative organizational policies. It acts strictly as a downstream consumer of deterministic data, ensuring that debt thresholds, score regressions, and forbidden rule patterns are evaluated consistently across CLI, REST API, CI/CD pipelines, and GitHub Pull Request Check Runs.

```
                  Repository / PR
                        ↓
            Entropy Static Analysis
                        ↓
         ┌──────────────────────────────┐
         │ Deterministic Findings Engine│
         │ Deterministic Scoring Engine │
         │ Phase 10 Comparison Engine   │
         └──────────────┬───────────────┘
                        ↓
                  Policy Engine
           (Pure, Deterministic, No AI)
                        ↓
               PASS  /  WARN  /  FAIL
                        ↓
       ┌────────────────┼────────────────┐
       ↓                ↓                ↓
   CLI Gates        REST API     GitHub Check Runs
  (Exit 0/1/2)   (/api/v1/policies) (Neutral/Fail/Pass)
```

### Strict Non-Negotiable Invariants
1. **100% Deterministic**: Identical scan, comparison, and policy configuration always yield identical policy evaluations.
2. **AI Never Controls Policy**: AI explanations remain strictly advisory. AI cannot approve a policy, override failures, or adjust thresholds.
3. **Entropy Scores Are Preserved**: Policy evaluation NEVER alters scores, findings, severities, or fingerprints.
4. **Zero Code Execution**: Policies are parsed as pure data schemas; arbitrary code, expressions, shell commands, or `eval`/`exec` are strictly rejected.
5. **Baseline Isolation**: Delta rules return `NOT_APPLICABLE` on standalone scans without fabricating baselines or treating absolute values as deltas.

---

## 2. Policy Configuration Schema

Policies can be authored in YAML or JSON. Unknown fields and negative thresholds are rejected at parse time.

```yaml
policy:
  name: default
  description: Default Entropy Organizational Debt Policy
  enabled: true
  version: "1.0.0"

  score:
    max_score: 80       # Absolute Entropy score limit (Fail if score > 80)
    max_delta: 5        # Maximum score increase in PR (Fail if delta > 5)
    warn_score: 60      # Warning threshold for overall score
    warn_delta: 2       # Warning threshold for score increase

  findings:
    max_new: 20         # Maximum new findings allowed in PR
    max_new_high: 2     # Maximum new High-severity findings
    max_new_critical: 0 # Zero-tolerance for new Critical-severity debt
    max_total: 200      # Absolute finding count limit
    max_total_high: 20  # Absolute High-severity finding limit
    max_total_critical: 5

  categories:
    max_score:
      error_handling: 50.0
      logging_and_secrets: 40.0
    max_delta:
      error_handling: 5.0
      logging_and_secrets: 3.0
    warn_delta:
      logging_and_secrets: 1.0

  rules:
    forbidden_rules:
      - ENT-LOG-002     # Hardcoded plain-text credentials
      - ENT-ERR-001     # Silent empty exception handlers
```

---

## 3. Supported Policy Rules

| Rule Name | Rule Type | Config Path | Description & Failure Semantics |
| :--- | :--- | :--- | :--- |
| `max_score` | Absolute | `score.max_score` | Fails if `current_score > max_score`. |
| `warn_score` | Absolute | `score.warn_score` | Warns if `current_score > warn_score` (and `<= max_score`). |
| `max_delta` | Delta | `score.max_delta` | Fails if `score_delta > max_delta`. Returns `NOT_APPLICABLE` without baseline. |
| `warn_delta` | Delta | `score.warn_delta` | Warns if `score_delta > warn_delta`. Returns `NOT_APPLICABLE` without baseline. |
| `max_new_findings` | Delta | `findings.max_new` | Fails if new findings count `> max_new`. Returns `NOT_APPLICABLE` without baseline. |
| `max_new_high` | Delta | `findings.max_new_high` | Fails if newly introduced High-severity findings `> max_new_high`. Returns `NOT_APPLICABLE` without baseline. |
| `max_new_critical`| Delta | `findings.max_new_critical`| Fails if newly introduced Critical-severity findings `> max_new_critical`. |
| `max_total_findings` | Absolute | `findings.max_total` | Fails if total findings count `> max_total`. |
| `max_total_high` | Absolute | `findings.max_total_high` | Fails if total High findings `> max_total_high`. |
| `max_total_critical` | Absolute | `findings.max_total_critical`| Fails if total Critical findings `> max_total_critical`. |
| `max_category_score` | Absolute | `categories.max_score[category]` | Fails if category debt score `> threshold`. |
| `max_category_delta` | Delta | `categories.max_delta[category]` | Fails if category delta `> threshold`. Returns `NOT_APPLICABLE` without baseline. |
| `warn_category_delta`| Delta | `categories.warn_delta[category]`| Warns if category delta `> threshold`. Returns `NOT_APPLICABLE` without baseline. |
| `forbidden_rules` | Hybrid | `rules.forbidden_rules` | Fails if any forbidden rule is introduced (in PR) or present (in standalone scan). |

---

## 4. Evaluation Semantics (PASS / WARN / FAIL)

- **`FAIL`**: One or more blocking rules were violated (`status == FAIL`, `passed == False`).
- **`WARN`**: No blocking rules violated, but one or more warning thresholds were exceeded (`status == WARN`, `passed == True`).
- **`PASS`**: All evaluated rules were satisfied within configured bounds (`status == PASS`, `passed == True`).
- **`NOT_APPLICABLE`**: Applied to delta rules when evaluating standalone scans without a baseline comparison.

Every violation and warning records:
- **`rule_name`**: Name of the rule triggered.
- **`rule_type`**: `absolute` or `delta`.
- **`threshold`**: Configured limit.
- **`actual_value`**: Measured score, delta, or count.
- **`message`**: Explainable description of the violation.
- **`finding_ids`**: Specific finding IDs responsible for the violation.

---

## 5. Command-Line Interface (CLI) & CI/CD Integration

Entropy provides an executable CLI: `entropy policy [validate|evaluate]`.

### Deterministic Exit Codes
- **`0`**: **PASS** (or **WARN** when `--fail-on-warn` is omitted).
- **`1`**: **POLICY FAIL** (or **WARN** when `--fail-on-warn` is supplied).
- **`2`**: **CONFIGURATION / ARGUMENT ERROR** (malformed policy, invalid categories).
- **`3`**: **ANALYSIS / SYSTEM ERROR** (missing comparison file, database read error).

### Commands
```bash
# Validate policy configuration
entropy policy validate policy.yaml

# Evaluate comparison artifact in CI
entropy policy evaluate --comparison-file comp.json --policy policy.yaml

# Treat warnings as blocking failure in CI
entropy policy evaluate --comparison-file comp.json --policy policy.yaml --fail-on-warn

# Output machine-readable JSON
entropy policy evaluate --comparison-file comp.json --json
```

### GitHub Actions Workflow Example
```yaml
name: Entropy Debt Gate
on: [pull_request]

jobs:
  entropy-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install Entropy CLI
        run: pip install entropy-backend
      - name: Validate Policy
        run: entropy policy validate .entropy-policy.yaml
      - name: Evaluate PR Comparison
        run: entropy policy evaluate --comparison-file .entropy/pr-comparison.json --policy .entropy-policy.yaml
```

---

## 6. GitHub Integration & Check Run Reporting

In Phase 12 PR workflows, the Policy Engine evaluates the scan comparison immediately after computation:
1. **GitHub Check Run Conclusion**:
   - `PASS` → `conclusion="success"`
   - `WARN` → `conclusion="neutral"`
   - `FAIL` → `conclusion="failure"` (informational status check; non-blocking unless marked required by repo admins).
2. **Check Run Details**:
   - Title: `Entropy Debt Score: 24/100 (+4) — Policy: FAIL`
   - Policy breakdown section listing all blocking violations and warnings.
3. **PR Markdown Comment**:
   - Includes Policy Decision row with status badges and violation summaries.
4. **Persistence**:
   - `policy_status` and `policy_evaluation_json` stored in SQLite `pr_analyses` table.

---

## 7. REST API Endpoints

- `GET /api/v1/policies`: List available policies.
- `GET /api/v1/policies/default`: Retrieve the default system policy.
- `POST /api/v1/policies/validate`: Validate policy YAML or JSON payload.
- `POST /api/v1/policies/scans/{scan_id}/evaluate`: Evaluate standalone scan.
- `POST /api/v1/policies/scans/{current_scan_id}/compare/{previous_scan_id}/evaluate`: Evaluate scan comparison.
- `GET /api/v1/policies/github/prs/{analysis_id}/policy`: Fetch policy evaluation for PR analysis run.

---

## 8. Security & Sandbox Invariants

- **Safe Deserialization**: Uses `yaml.safe_load()` exclusively. Custom constructor tags (`!!python/object/...`) are rejected.
- **Strict Schema Enforcement**: Extra fields are rejected via `ConfigDict(extra="forbid")`. Arbitrary executable directives (`command`, `exec`, `eval`) are rejected before execution.
- **Advisory AI Isolation**: LLM outputs never participate in policy evaluations or threshold calculations.

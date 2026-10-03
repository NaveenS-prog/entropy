# Finding Suppressions & Audit Trails

Entropy provides deterministic, auditable suppression of debt findings through inline code comments and project-level configuration.

---

## 1. Core Principles

1. **Deterministic & Strict Rule IDs:** Only recognized 38 Entropy rule IDs (such as `ENT-ERR-001`, `ENT-AUTH-002`, `ENT-DUP-001`) may be suppressed. Specifying unknown rule IDs triggers a configuration/validation error.
2. **Zero Score Impact:** Suppressed findings NEVER contribute to the Entropy Score or category score breakdowns.
3. **Preserved Audit Trail:** Suppressed findings are NOT silently dropped. They are retained in the finding inventory with `is_suppressed=True`, `status="suppressed"`, `suppression_source`, and `suppression_reason`.
4. **Visibility in CLI & UI:** Developers can inspect suppressed findings via `entropy findings --suppressed` and in the web dashboard with dedicated suppression badges.

---

## 2. Inline Comment Suppressions

Inline suppressions are placed on the finding line or the line directly preceding it.

### Syntax
- **Python:** `# entropy: ignore[RULE-ID]` or `# entropy: ignore[RULE-ID]: <reason>`
- **JavaScript / TypeScript:** `// entropy: ignore[RULE-ID]` or `/* entropy: ignore[RULE-ID] */`

### Multiple Rules
Multiple rule IDs can be ignored in a single comment using comma separation:
```python
# entropy: ignore[ENT-ERR-001, ENT-ERR-002]: Legacy third-party library interface
try:
    legacy_driver.connect()
except:
    pass
```

### Line Proximity
An inline suppression comment is matched if it appears anywhere between `line_start - 1` and `line_end` of the finding evidence span.

---

## 3. Configuration-Level Suppressions

For repository-wide or directory-wide exceptions, declare suppressions under `.entropy.yml`:

```yaml
suppressions:
  rules:
    - rule_id: "ENT-LOG-001"
      reason: "Debug logger in benchmark test runner"
      paths:
        - "benchmarks/**"
```

Each configured suppression must include an explicit, non-empty `reason`.

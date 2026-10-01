# Entropy Analyzer Authoring Specification

## 1. Analyzer Design Contract

Every analyzer in Entropy must inherit from `BaseAnalyzer` and adhere to the following contract:

```python
from app.analyzers.base import BaseAnalyzer, AnalysisContext
from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition

class CustomAnalyzer(BaseAnalyzer):
    @property
    def analyzer_id(self) -> str:
        """Unique snake_case identifier."""
        return "custom_debt_analyzer"

    @property
    def name(self) -> str:
        """Human-readable name."""
        return "Custom Debt Analyzer"

    @property
    def category(self) -> DebtCategory:
        """The MVP DebtCategory contributed to."""
        return DebtCategory.AUTHENTICATION_CONSISTENCY

    @property
    def supported_languages(self) -> set[SupportedLanguage]:
        return {SupportedLanguage.PYTHON}

    @property
    def rules(self) -> list[RuleDefinition]:
        return [RULE_AUTH_001]

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Execute deterministic AST visitor analysis."""
        ...
```

---

## 2. Using `AnalysisContext`

`AnalysisContext` provides read-only access to all discovered and parsed files in the repository:

- `context.get_files_for_language(SupportedLanguage.PYTHON)`: Returns only valid parsed files for Python.
- `context.get_file(relative_path)`: Resolves a file by relative path.
- `context.total_loc`: Total codebase lines of code.
- `context.repo_path`: Target root path.

---

## 3. Finding Construction Rules

Every generated `Finding` must satisfy:

1. **Exact Source Location**:
   `line_start` and `line_end` must match the exact lines where the pattern occurred in source code.
2. **Verbatim Code Evidence**:
   Extracted using `parsed_file.extract_snippet(line_start, line_end)`.
3. **Deterministic Fingerprint**:
   Created via `Finding.generate_fingerprint(rule_id, file, symbol, pattern_signature)`.
4. **Actionable Recommendation**:
   Must describe the clean architectural replacement rather than simply complaining about the problem.
5. **Impact Statement**:
   Must explain why the pattern accumulates debt or future security risk.

---

## 4. Testing Requirements

Every analyzer rule must have unit tests covering:
- Positive detection: Syntactically proving that the pattern triggers a finding.
- Negative verification: Proving that clean, idiomatic code yields **zero** findings.
- Parse resilience: Ensuring that unparseable or broken files do not crash the analyzer.

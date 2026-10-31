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

---

## 5. Multi-Language Adapter Architecture

Entropy provides modular language adapters isolating language-specific parsing, internal deterministic rules, and optional external tools behind `BaseLanguageAdapter`:

```python
from app.analyzers.adapters.base import BaseLanguageAdapter, ToolStatus
from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.parser.base import ParsedFile

class ExampleLanguageAdapter(BaseLanguageAdapter):
    @property
    def language(self) -> SupportedLanguage:
        return SupportedLanguage.GO

    @property
    def name(self) -> str:
        return "Example Go Adapter"

    @property
    def supported_categories(self) -> set[DebtCategory]:
        return {DebtCategory.INPUT_VALIDATION, DebtCategory.ARCHITECTURAL_CONSISTENCY}

    @property
    def rules(self) -> list[RuleDefinition]:
        return [RULE_GO_001, RULE_GO_002]

    def analyze_file(self, file: ParsedFile) -> list[Finding]:
        # Deterministic internal AST/token inspection
        return check_rules(file)

    def check_tool_availability(self) -> ToolStatus:
        # Probe PATH for optional external tools (e.g. gosec)
        ...
```

### Supported Languages & Implemented Rule Sets

| Language | Adapter | Rules Implemented | Debt Category | Severity | Limitations & Soundness |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **C** | `CLanguageAdapter` | `ENT-C-001` (Unsafe buffer/string operations: `strcpy`, `strcat`, `gets`, `sprintf`)<br>`ENT-C-002` (Unsafe formatted input: `scanf %s`)<br>`ENT-C-003` (Dangerous command execution: `system`, `popen`) | `INPUT_VALIDATION` | HIGH / CRITICAL | Relies on static syntactic pattern matching without symbolic execution or pointer-alias tracking. Safe bounded counterparts (`strncpy`, `fgets`, `snprintf`) are not flagged. |
| **C++** | `CppLanguageAdapter` | `ENT-CPP-001` (Unmanaged dynamic memory: raw `new`/`delete`)<br>`ENT-CPP-002` (Type punning with `reinterpret_cast`)<br>`ENT-CPP-003` (Legacy C string functions in C++) | `INPUT_VALIDATION` & `ARCHITECTURAL_CONSISTENCY` | MEDIUM / HIGH | Detects raw allocation anti-patterns vs modern RAII smart pointers (`std::unique_ptr`). Does not inspect custom allocators. |
| **Rust** | `RustLanguageAdapter` | `ENT-RUST-001` (Review-worthy `unsafe` block / fn)<br>`ENT-RUST-002` (High-risk `mem::transmute`)<br>`ENT-RUST-003` (Raw pointer dereferencing `*ptr`) | `ARCHITECTURAL_CONSISTENCY` & `INPUT_VALIDATION` | LOW (unsafe) / MEDIUM / HIGH | **Critical Soundness Invariant**: Rust `unsafe` is classified as `Severity.LOW` review-worthy debt/observation, **NOT** automatically treated as a confirmed vulnerability. |
| **Java** | `JavaLanguageAdapter` | `ENT-JAVA-001` (SQL injection via concatenation in JDBC query/statement)<br>`ENT-JAVA-002` (Unsafe deserialization: `readObject`)<br>`ENT-JAVA-003` (Command execution: `Runtime.getRuntime().exec`) | `INPUT_VALIDATION` | HIGH / CRITICAL | Parameterized queries with `PreparedStatement` and `?` placeholders are clean. Advanced taint analysis across inter-procedural call graphs is not performed. |
| **Go** | `GoLanguageAdapter` | `ENT-GO-001` (SQL injection via `fmt.Sprintf` / concatenation in query)<br>`ENT-GO-002` (Insecure TLS: `InsecureSkipVerify: true`)<br>`ENT-GO-003` (Memory bypass via `unsafe.Pointer`)<br>`ENT-GO-004` (Command injection via `exec.Command` shell invocation) | `INPUT_VALIDATION` & `ARCHITECTURAL_CONSISTENCY` | MEDIUM / HIGH | Parameterized queries (`db.Query("... WHERE id = ?", id)`) and direct executable invocations without shell interpreters are clean. |
| **JavaScript** | `JavaScriptLanguageAdapter` | `ENT-JS-002` (Dynamic code evaluation: `eval()`, `new Function()`)<br>`ENT-JS-003` (Unsafe DOM injection: `innerHTML`, `outerHTML`, `document.write`) | `INPUT_VALIDATION` | HIGH / CRITICAL | Complementary to Python/JS AST rules; runs in addition to web framework route analyzers. Safe DOM manipulation via `textContent` is clean. |
| **TypeScript** | `TypeScriptLanguageAdapter` | `ENT-TS-001` (Type assertion bypass: `as any`, `<any>`)<br>`ENT-TS-002` (Compiler suppression: `// @ts-ignore`, `// @ts-nocheck`)<br>`ENT-TS-003` (Non-null assertion on external request boundary: `req.body!.prop!`) | `ARCHITECTURAL_CONSISTENCY` | LOW / MEDIUM | **Explicit Attribution**: Runs exclusively on `.ts`/`.tsx` files and attributes findings to `SupportedLanguage.TYPESCRIPT`. Safe type guards and schema parsers (Zod) are clean. |
| **PHP** | `PhpLanguageAdapter` | `ENT-PHP-001` (SQL injection via string concatenation `.` in query)<br>`ENT-PHP-002` (Arbitrary code/command execution: `eval`, `system`, `exec`, `shell_exec`, `passthru`)<br>`ENT-PHP-003` (Unsafe dynamic file inclusion: `include $file`, `require $_GET[...]`) | `INPUT_VALIDATION` | HIGH / CRITICAL | Static includes and PDO parameterized queries (`$stmt->execute(['id' => $id])`) are clean. |

---

## 6. Optional External Tool Integration & Availability Requirements

Entropy is self-contained: all internal rules execute deterministically with zero external tool dependencies. When mature external security tools are installed on the host system PATH, adapters can optionally invoke them and normalize their output:

| Language | Optional Tool | Installation Command | Probed Executable | Normalization Target |
| :--- | :--- | :--- | :--- | :--- |
| **C / C++** | `cppcheck` | `sudo apt-get install cppcheck` | `cppcheck` | `--enable=warning,style --xml` |
| **C / C++** | `clang-tidy` | `sudo apt-get install clang-tidy` | `clang-tidy` | `-checks=cert-*,bugprone-*` |
| **Rust** | `cargo-audit` | `cargo install cargo-audit` | `cargo-audit` | `cargo audit --json` |
| **Go** | `gosec` | `go install github.com/securego/gosec/v2/cmd/gosec@latest` | `gosec` | `-fmt=json` |
| **PHP** | `phpstan` / `psalm` | `composer require --dev phpstan/phpstan` | `phpstan` | `analyse --error-format=json` |

When an external tool is missing, the adapter reports `available: false` via `ToolStatus` and continues scanning with its internal rules without crashing or aborting the scan.

---

## 7. How to Add a New Language Adapter

To add support for a new programming language (e.g., Ruby, Kotlin, Swift):

1. **Add Language Enum**: Add the language identifier to `SupportedLanguage` in `app/models/domain/enums.py`.
2. **Configure File Extensions**: Add file extensions (e.g., `.rb`, `.kt`, `.swift`) to `EXTENSION_LANGUAGE_MAP` in `app/repository/language.py` and `ALL_SUPPORTED_LANGUAGES`.
3. **Define Language Rules**: Create rules in `app/analyzers/adapters/<lang>/<lang>_rules.py` with unique rule IDs (e.g., `ENT-RB-001`), descriptions, severities, remediations, and standard references.
4. **Implement BaseLanguageAdapter**: Subclass `BaseLanguageAdapter` in `app/analyzers/adapters/<lang>/<lang>_adapter.py`. Implement `language`, `name`, `supported_categories`, `rules`, and `analyze_file(file)`.
5. **Register in Registry**: Add the new adapter to `LanguageAdapterRegistry._register_defaults()` in `app/analyzers/adapters/registry.py`.
6. **Add Test Fixtures**: Place safe `vulnerable.<ext>` and `clean.<ext>` test files in `tests/fixtures/language_adapters/<lang>/`.
7. **Write Unit Tests**: Add test assertions in `tests/unit/test_language_adapter_rules.py` verifying precision, zero false positives on clean code, and correct finding normalization.

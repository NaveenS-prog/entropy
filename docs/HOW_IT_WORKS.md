# How Entropy Works: Architecture, Detection Mechanics, and Mathematical Scoring

> **Authoritative Technical Deep Dive & System Specification**  
> *Repository:* [github.com/NaveenS-prog/entropy](https://github.com/NaveenS-prog/entropy)

---

## 1. Executive Summary & Core Constraints

Entropy is an **Architectural Security-Debt Analyzer** designed specifically for codebases built with or without generative AI assistance. Rather than hunting for transient, point-in-time runtime exploits (like DAST or CVE dependency scanners), Entropy identifies **structural decay, architectural fragmentation, missing security boundaries, and swallowed failures** that accumulate hidden risk over time.

To ensure developer trust and mathematical validity, Entropy is engineered under three strict constitutional axioms:

```
┌────────────────────────────────────────────────────────────────────────┐
│                      THE 3 CONSTITUTIONAL AXIOMS                       │
├────────────────────────────────────────────────────────────────────────┤
│ 1. The Non-Attribution Covenant: Entropy NEVER predicts "AI code" or   │
│    calculates "AI percentages". It only evaluates concrete syntax.     │
│ 2. Zero Code Execution: Repositories are treated as passive text. No   │
│    scanned module is EVER imported, executed, or eval'd.               │
│ 3. Deterministic Scoring: The 0–100 score is a pure mathematical      │
│    function of AST syntax and LOC. AI never calculates scores.        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. End-to-End System Topology

The following diagram illustrates the complete dataflow when a scan is executed via the CLI (`entropy scan .`) or API (`POST /api/v1/scans`):

```mermaid
flowchart TD
    subgraph S1 ["Stage 1: Discovery & Scoping"]
        Repo["Source Repository"] --> Discovery["RepositoryDiscoverer & Scanner"]
        Discovery --> GitIgnore[".gitignore Filter (pathspec)"]
        GitIgnore --> ScopeFilter["Scope Filter (Excludes tests/mocks)"]
    end

    subgraph S2 ["Stage 2 & 3: AST Parsing & Context"]
        ScopeFilter --> PyParse["Python AST Parser (ast.NodeVisitor)"]
        ScopeFilter --> JSParse["JS/TS Parser & Visitor"]
        PyParse --> Context["AnalysisContext Construction"]
        JSParse --> Context
        Context --> DepGraph["Module Dependency Graph"]
    end

    subgraph S3 ["Stage 4: 7 Static Analysis Engines"]
        Context --> A1["Error Handling Engine"]
        Context --> A2["Authentication Engine"]
        Context --> A3["Authorization Engine"]
        Context --> A4["Input Validation Engine"]
        Context --> A5["Logging & Secrets Engine"]
        Context --> A6["Architectural Consistency Engine"]
        Context --> A7["Code Duplication Engine"]
    end

    subgraph S4 ["Stage 5 & 6: Fingerprinting & Scoring"]
        A1 & A2 & A3 & A4 & A5 & A6 & A7 --> Findings["Finding Generation"]
        Findings --> FP["Line-Drift Invariant SHA-256 Fingerprinting"]
        FP --> Scorer["Mathematical Scoring Engine"]
        Scorer --> Diminish["Logarithmic Diminishing Returns"]
        Diminish --> Density["KLOC Density Normalization"]
        Density --> Saturation["Asymptotic Exponential Saturation"]
        Saturation --> Floors["Severity Floor Protection"]
        Floors --> FinalScore["Final Entropy Score (0–100)"]
    end

    subgraph S5 ["Stage 7 & 8: Policy, AI & Reporting"]
        FinalScore --> PolicyEngine["Policy Evaluator (.entropy-policy.yaml)"]
        FinalScore --> BaselineComp["Baseline Comparison (New/Resolved/Persistent)"]
        Findings -.-> Redaction["Secret & PII Redaction Pipeline"]
        Redaction -.-> LLM["Advisory AI (Gemini Refactor Diffs)"]
        PolicyEngine --> Outputs["CLI / SARIF 2.1.0 / Next.js Dashboard"]
    end
```

---

## 3. Stage 1: Safe Ingestion & Discovery

File discovery is handled by `RepositoryScanner` and `RepositoryDiscoverer` in `backend/app/repository/`.

### 3.1 Zero-Code-Execution Invariant
Traditional Python analysis tools often rely on `importlib` or inspect running modules. In contrast, Entropy enforces a strict sandbox:
- Target files are **never** imported into `sys.modules`.
- Target code is parsed purely as string data into compiler AST nodes.
- No `setup.py`, build scripts, or arbitrary code can execute during a scan.

### 3.2 Gitignore and Scope Filtering
1. **`.gitignore` Hierarchy**: Entropy evaluates root and nested `.gitignore` files using `pathspec`, preventing `node_modules/`, `__pycache__/`, `.venv/`, and build artifacts from contaminating analysis.
2. **Production Scoping (`is_scope_excluded`)**:
   Non-production directories are excluded by default to avoid penalizing test mocks or documentation:
   - Test directories: `tests/`, `test/`, `__tests__/`, `spec/`
   - Test files: `test_*.py`, `*_test.py`, `*.spec.ts`, `*.test.js`
   - Non-production assets: `fixtures/`, `mocks/`, `examples/`, `docs/`, `bench/`
3. **Safety Thresholds**:
   - Files $> 2\text{ MB}$ (`MAX_FILE_SIZE_BYTES`) are skipped with a warning.
   - Non-UTF-8 binary files (detected via null-byte inspection `b'\x00'`) are omitted.
   - Symlinks pointing outside the repository root are ignored to prevent path traversal attacks.

---

## 4. Stage 2 & 3: Multi-Language AST Parsing & Semantic Context

### 4.1 Python AST Parser (`PythonAstParser`)
- Uses Python's native `ast` library.
- Custom visitors traverse the AST to extract:
  - Top-level and nested classes and functions.
  - Decorator expressions and arguments (e.g. `@app.get("/users")`, `@login_required`).
  - Exception handler blocks (`ast.Try`, `ast.ExceptHandler`).
  - Import declarations (`ast.Import`, `ast.ImportFrom`), categorizing them into standard library, third-party, and local internal imports.
  - Assignment nodes and string literals for credential/entropy scanning.

### 4.2 JavaScript & TypeScript CST Parser (`JSTSParser`)
- Parses `.js`, `.jsx`, `.ts`, and `.tsx` source trees without requiring Node.js runtime execution.
- Extracts Express/Fastify/Next.js/Hono/NestJS routing patterns, middleware registrations (`app.use`, `router.use`), route guards, and SQL template literals.

### 4.3 Semantic Context (`AnalysisContext`)
The parser populates an immutable `AnalysisContext` containing:
- In-memory representations of all valid parsed files.
- Aggregate metrics: `total_loc`, `scannable_files`, `excluded_loc`.
- Pre-built module dependency indices.

---

## 5. Stage 4: The 7 Static Analysis Engines (How Everything is Checked)

Entropy organizes its static analysis rules into seven distinct architectural categories. Each analyzer operates deterministically on AST syntax.

```
┌────────────────────────────────────────────────────────────────────────┐
│                       THE 7 DEBT CATEGORIES                            │
├──────────────────────────────┬────────┬────────────────────────────────┤
│ Category                     │ Weight │ Key Target Patterns            │
├──────────────────────────────┼────────┼────────────────────────────────┤
│ Authentication Consistency   │  0.20  │ Missing guards, route bypass   │
│ Authorization Consistency    │  0.20  │ Missing RBAC on mutating ops   │
│ Error Handling Debt          │  0.15  │ Swallowed errors, bare excepts │
│ Input Validation Debt        │  0.15  │ Raw SQL sinks, missing schemas │
│ Logging & Secrets Debt       │  0.15  │ Shannon entropy >3.2, secrets  │
│ Architectural Consistency    │  0.10  │ Circular imports, layer bypass │
│ Code Duplication Debt        │  0.05  │ AST clone subtree clusters     │
└──────────────────────────────┴────────┴────────────────────────────────┘
```

---

### 5.1 Error Handling Debt Engine
*Code location: `backend/app/analyzers/rules/error_handling/` and `backend/app/analyzers/jsts_rules/error_handling.py`*

Swallowing errors masks authentication failures, crypto errors, and database corruptions. The analyzer inspects every `try...except` and `try...catch` block:

1. **`ENT-ERR-001` (Bare Except Clause)**:
   - Detects `except:` without an exception type.
   - *Why it matters*: In Python, a bare except catches `BaseException`, including `KeyboardInterrupt` and `SystemExit`, preventing clean shutdowns and masking critical system signals.
2. **`ENT-ERR-002` (Broad Exception Handler)**:
   - Detects `except Exception:` or `except BaseException:`.
   - Flags handlers catching top-level broad types unless accompanied by specialized handling.
3. **`ENT-ERR-003` (Empty Exception Handler)**:
   - Inspects the statement body of the exception handler.
   - An empty body consists solely of `pass`, `...` (Ellipsis), or a standalone string docstring.
4. **`ENT-ERR-004` (Silently Swallowed Exception)**:
   - Inspects the AST subtree of the handler body.
   - A handler is flagged if it catches an exception but contains:
     - No `ast.Raise` statement (does not re-raise or wrap).
     - No logging invocation (scans for `logger.error`, `logging.exception`, `sentry_sdk`, etc.).
5. **`ENT-ERR-005` (Generic Fallback Return)**:
   - Detects handlers that catch exceptions and return generic falsy values (`return None`, `return False`, `return {}`, `return []`) without logging or re-raising.
6. **`ENT-ERR-JS-001` & `ENT-ERR-JS-002` (JavaScript/TypeScript Catch Blocks)**:
   - Identifies empty `catch (err) {}` blocks and catch blocks returning default objects without logging to console/pino/winston.

---

### 5.2 Authentication Consistency Engine
*Code location: `backend/app/analyzers/security/auth/` and `backend/app/analyzers/jsts_rules/`*

Detects unprotected endpoints and inconsistent authentication boundaries across **8 web frameworks**:
- **Python**: FastAPI (`Depends`, `Security`), Flask (`@login_required`), Django (`@login_required`, FBVs, and CBV `LoginRequiredMixin`).
- **JavaScript/TypeScript**: Express (`app.use`, route handlers), Fastify (`preHandler`, hooks), Next.js (App Router `route.ts`, Pages API `pages/api/`, `middleware.ts`), Hono (`c.get('user')`, middleware), NestJS (`@UseGuards`, `@Public`).

#### How Route Detection & Inspection Works:
1. **Endpoint Extraction**:
   - FastAPI: Tracks `@app.get`, `@router.post`, `APIRouter(dependencies=[...])`.
   - Express/Fastify: Tracks `app.get('/path', ...)`, `router.post('/path', ...)`.
   - Next.js: Analyzes exported HTTP functions (`GET`, `POST`, `DELETE`, etc.) in `route.ts` files.
2. **Registration Ordering in Middleware**:
   - In Express and Fastify, `app.use(authMiddleware)` only protects routes declared *after* that statement in the file.
   - Entropy evaluates line numbers: any route registered *above* the middleware statement is treated as unprotected.
3. **Mount-Path Scoping**:
   - `app.use('/api', authMiddleware)` applies only to endpoints whose path starts with `/api`. An endpoint at `/health` or `/admin` outside `/api` is evaluated independently.
4. **Trivial Pass-Through Inspection**:
   - If middleware is defined in the same repository, Entropy parses its AST body.
   - If the function trivially executes `next()` or returns without inspecting headers, cookies, tokens, sessions, or `req.user`, it is rejected as an authentication guard.
5. **Public Route Matching with Deny-List Overrides**:
   - Paths matching known public patterns (e.g. `/login`, `/signup`, `/healthz`, `/metrics`, `/docs`) are exempt from authentication findings.
   - **Deny-List Override**: If any path segment contains sensitive terms (`admin`, `manage`, `internal`, `root`, `delete`, `payment`, `export`, `refund`), public status is **strictly denied**. An endpoint at `/api/v1/public/admin/delete` can never be considered intentionally public.
6. **State-Changing Method Restrictions**:
   - State-changing HTTP methods (`POST`, `PUT`, `DELETE`, `PATCH`) on public paths require explicit allowlisting (e.g. `/login`, `/register`). An unprotected `DELETE /public/item` is immediately flagged.

---

### 5.3 Authorization Consistency Engine
*Code location: `backend/app/analyzers/security/auth/authorization.py` and `backend/app/analyzers/jsts_rules/authorization.py`*

Authentication verifies *who* the caller is; authorization verifies *what* they are permitted to do.

1. **`ENT-AUTHZ-001` (Unprotected Privileged Endpoint)**:
   - Identifies endpoints with authenticated identities that lack Role-Based Access Control (RBAC) or permission checks.
   - Specifically flags endpoints matching sensitive paths (`/admin/*`, `/manage/*`, `/billing/*`) or performing destructive actions (`POST`, `PUT`, `DELETE`, `PATCH`) where only authentication (e.g., valid JWT) is checked, but no role/scope requirement (`require_admin`, `@Roles('admin')`, `user.has_perm`) exists.
2. **`ENT-AUTHZ-002` (Inconsistent Authorization in Route Groups)**:
   - If 4 out of 5 endpoints in the `/api/v1/billing` group enforce `@require_role('billing_admin')`, but 1 endpoint omits the check, the anomaly is flagged as authorization inconsistency.

---

### 5.4 Input Validation Debt Engine
*Code location: `backend/app/analyzers/security/validation/` and `backend/app/analyzers/jsts_rules/input_validation.py`*

Flags untrusted request data entering execution sinks or state-changing flows without schema validation.

1. **`ENT-INPUT-001` (Missing Schema Validation)**:
   - In FastAPI: Checks parameter annotations for Pydantic models (classes ending in `Schema`, `Request`, `DTO`, `Input`). Flagged if sensitive routes accept unconstrained `dict`, `Any`, or raw strings.
   - In Express/Next.js: Inspects route handlers for Zod (`schema.parse`), Joi (`schema.validate`), or Yup validation before handling payload data.
2. **`ENT-INPUT-003` & `ENT-INPUT-JS-001` (Raw Execution Sinks)**:
   - AST taint tracking detects untrusted parameters flowing directly into:
     - SQL execution sinks: `cursor.execute(f"SELECT ... {param}")`, `session.execute(text(...))`, raw string concatenations, or JavaScript template literals `db.query(\`SELECT ... ${id}\`)`.
     - Subprocess/Command execution: `subprocess.Popen(f"...", shell=True)`, `os.system(...)`, `child_process.exec(...)`.

---

### 5.5 Logging & Secrets Debt Engine
*Code location: `backend/app/analyzers/security/logging_secrets/` and `backend/app/analyzers/jsts_rules/logging_secrets.py`*

Identifies hardcoded credentials and dangerous data leakage into application log streams.

1. **`ENT-LOG-001` (Unredacted Sensitive Logging)**:
   - Tracks logging calls (`logger.info`, `console.log`, `winston`, `pino`).
   - Flags log expressions outputting variables with sensitive names (`password`, `access_token`, `secret`, `api_key`, `credit_card`) unless safe wrappers (`mask(...)`, `redact(...)`, `hash(...)`) are detected.
2. **`ENT-LOG-002` (Hardcoded Secret Detection via Shannon Entropy)**:
   - String literals assigned to variables or constants are evaluated using **Shannon Entropy**:
     $$H(S) = -\sum_{i=1}^{n} p(c_i) \log_2 p(c_i)$$
     where $p(c_i)$ is the frequency of character $c_i$ in string $S$.
   - Strings with length between 16 and 128 characters exhibiting high randomness ($H > 3.2$) combined with variable names like `KEY`, `TOKEN`, `SECRET`, or `PASS` trigger `CRITICAL` findings.
   - Matches known high-confidence live prefixes:
     - AWS: `AKIA...`
     - GitHub: `ghp_...`, `gho_...`
     - Stripe: `sk_live_...`, `rk_live_...`
     - Slack: `xoxb-...`, `xoxp-...`
     - Private Keys: `-----BEGIN RSA PRIVATE KEY-----`
   - Common test placeholders (`dummy`, `changeme`, `your_api_key`, `test`) are filtered to prevent false positives.

---

### 5.6 Architectural Consistency Engine
*Code location: `backend/app/analyzers/architecture/`*

Maintains structural coherence by inspecting module dependencies and layer boundaries.

1. **`ENT-ARCH-001` (Circular Module Dependencies)**:
   - Builds a directed graph $G = (V, E)$ where $V$ represents codebase modules and $E$ represents static import statements.
   - Ignores safe `if TYPE_CHECKING:` typing guards.
   - Runs **Tarjan's Strongly Connected Components (SCC)** algorithm to isolate cyclic subgraphs.
   - Performs deterministic DFS within each non-trivial SCC to extract elementary cycles.
   - **Canonical Cycle Normalization**: To prevent duplicate reporting of the same cycle starting at different nodes (e.g. $A \to B \to C \to A$ vs $B \to C \to A \to B$), cycles are normalized to start with the lexicographically smallest module name.
2. **`ENT-ARCH-002` (Layer Boundary Violations)**:
   - Classifies modules into layers: `API` (routes/controllers), `SERVICE` (business logic), `REPOSITORY` (database queries/models).
   - If an architectural pattern establishes that API routes communicate through Services, API modules that directly bypass the Service layer to execute Repository SQL are flagged.
3. **`ENT-ARCH-005` & `ENT-ARCH-006` (God Modules & God Classes)**:
   - Identifies modules $> 1,000\text{ LOC}$ with extreme afferent/efferent coupling or classes $> 500\text{ LOC}$ with $> 20$ methods.

---

### 5.7 Code Duplication & Boilerplate Engine
*Code location: `backend/app/analyzers/duplication/`*

AI coding assistants frequently duplicate code rather than extracting shared abstractions. Entropy detects structural clones using normalized AST subtrees.

1. **AST Subtree Normalization (`ASTNormalizer`)**:
   - **Variable & Parameter Anonymization**: All function parameters are renamed to canonical positional tokens (`$p1, $p2, \dots`). Local variable assignments are renamed to (`$v1, $v2, \dots`).
   - **Docstring & Comment Stripping**: Removes documentation, whitespace, and formatting differences.
   - **Operator & Constant Preservation**: Arithmetic and logical operators (`+`, `-`, `*`, `==`) and status codes (`200`, `404`) are preserved so semantically different logic is not conflated.
   - **Built-in Preservation**: Built-ins (`len`, `range`, `Exception`, `isinstance`) retain their identities.
2. **Exact Structural Clones (`ENT-DUP-001`)**:
   - Computes SHA-256 hash of the canonical AST structure. Functions with identical hashes across files represent copy-pasted implementations.
3. **Structurally Similar Functions (`ENT-DUP-002`)**:
   - Computes **Jaccard similarity** on the multiset of structural AST tokens:
     $$J(A, B) = \frac{|A \cap B|}{|A \cup B|}$$
   - Any function pair with $J(A, B) \ge 0.80$ is flagged for refactoring.
4. **Duplication Clusters (`ENT-DUP-005`)**:
   - Groups 3 or more structurally clone functions into an architectural duplication cluster.

---

## 6. Stage 5: Finding Generation & Line-Drift Invariant Fingerprinting

When an analyzer rule detects a defect, it constructs an immutable `Finding` object:

```python
@dataclass(frozen=True)
class Finding:
    id: str                 # Unique UUID
    rule_id: str            # e.g., "ENT-AUTH-001"
    category: DebtCategory  # e.g., DebtCategory.AUTHENTICATION_CONSISTENCY
    severity: Severity      # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: Confidence  # HIGH (1.0), MEDIUM (0.8), LOW (0.5)
    file: str               # Relative path from repository root
    line_start: int         # Exact starting line
    line_end: int           # Exact ending line
    symbol: str             # Enclosing function, class, or route
    evidence: CodeEvidence  # Verbatim lines extracted from source
    fingerprint: str        # Stable tracking hash across commits
```

### Line-Drift Invariant Fingerprinting
In continuous integration, adding a line of code at line 1 shifts all subsequent lines down. If fingerprints included line numbers, every finding would appear as "new" on every commit.

Entropy computes fingerprints strictly over structural invariants:

$$\text{Fingerprint} = \text{SHA256}(\text{rule\_id} \,\|\, \text{relative\_path} \,\|\, \text{symbol\_name} \,\|\, \text{ast\_signature})$$

This guarantees that as code shifts up or down within a file, Entropy tracks the finding across historical git commits with 100% stability.

---

## 7. Stage 6: The Mathematical Scoring Model (How Code is Scored)

The Entropy Scoring Engine transforms a collection of discrete findings into a unified, deterministic **Entropy Debt Score** between **0 and 100**.

```
  0 ────────────────── 20 ────────────────── 40 ────────────────── 60 ────────────────── 80 ────────────────── 100
  │     VERY LOW       │        LOW         │      MODERATE      │        HIGH        │      VERY HIGH      │
  │ Pristine codebase  │ Minor boilerplate  │ Attention required │ Critical defects   │ Severe architecture │
```

The mathematical model is derived in 5 distinct steps:

---

### Step 1: Raw Points & Rule-Level Logarithmic Diminishing Returns

Each individual finding $f$ generated by rule $r$ receives a base point value:

$$\text{Points}(f) = W_{\text{severity}}(f) \times M_{\text{confidence}}(f)$$

Where weights and multipliers are strictly centralized:
- **Severity Weights ($W_{\text{severity}}$)**:
  - `CRITICAL`: **10.0** (Admin bypass, hardcoded AWS keys, unauthenticated SQLi)
  - `HIGH`: **7.0** (Silently swallowed exceptions, unauthenticated read routes)
  - `MEDIUM`: **4.0** (Broad catch blocks, bare excepts, missing schemas)
  - `LOW`: **1.0** (Generic falsy fallback returns, minor boilerplate)
  - `INFO`: **0.0** (Telemetry notices)
- **Confidence Multipliers ($M_{\text{confidence}}$)**:
  - `HIGH`: **1.0** (100% deterministic AST match)
  - `MEDIUM`: **0.8** (Context-dependent pattern match)
  - `LOW`: **0.5** (Broad heuristic)

#### Diminishing Returns on Repetitive Rules
If a noisy rule fires 5,000 times across a repository, it should not push the score to 100 while obscuring all other categories. Findings exceeding $N = 20$ (`RULE_FULL_WEIGHT_THRESHOLD`) scale logarithmically:

$$\text{Penalty}(r) = \sum_{i=1}^{\min(k, 20)} \text{Points}(f_i) + \overline{\text{Points}}_r \times 5.0 \times \ln\left(1 + \frac{k - 20}{1.0}\right)$$

Where $\overline{\text{Points}}_r$ is the average point value of the first 20 findings. The raw category penalty is:

$$\text{Raw Penalty}_c = \sum_{r \in \text{Rules}_c} \text{Penalty}(r)$$

---

### Step 2: Codebase Scale & KLOC Density

To ensure **scale invariance** (a codebase with 1 defect per 100 lines receives the same score whether it is 500 lines or 500,000 lines), points are normalized by codebase volume.

To protect small repositories from division by near-zero, a scale floor ($\text{MIN\_LOC\_FLOOR} = 200$) is enforced:

$$\text{Effective LOC} = \max(\text{Total LOC}, 200)$$

$$\text{KLOC} = \frac{\text{Effective LOC}}{1000.0}$$

$$\text{Weighted Debt Density}_c = \frac{\text{Raw Penalty}_c}{\text{KLOC}} \quad (\text{points per KLOC})$$

---

### Step 3: Asymptotic Exponential Saturation

To map infinite density onto a bounded $[0, 100]$ score, an asymptotic exponential curve with saturation constant $K = 40.0$ (`DENSITY_SATURATION_FACTOR`) is applied:

$$\text{Category Score}_c = 100.0 \times \left(1.0 - e^{-\frac{\text{Weighted Debt Density}_c}{40.0}}\right)$$

```
Category Score
100 ┌─────────────────────────────────────────────── Maximum Theoretical Debt
 80 ├──────────────────────────────────────╭──────── VERY HIGH (81–100)
 60 ├─────────────────────────────╭────────┘         HIGH (61–80)
 40 ├──────────────╭──────────────┘                  MODERATE (41–60)
 20 ├─────╭────────┘                                 LOW (21–40)
  0 ┴─────┴───────────────────────────────────────── VERY LOW (0–20)
    0     10      20      30      40      50   Density (pts / KLOC)
```

---

### Step 4: Anti-Dilution Severity Floors

In massive repositories (e.g. 500,000 lines), pure density would dilute a critical defect (like a hardcoded production database password) down to a score of 0.1.

To prevent critical defects from being buried by codebase volume, Entropy enforces **Severity Floors**:

| Trigger Condition | Minimum Headline Score | Minimum Debt Tier |
| :--- | :---: | :---: |
| $\ge 1$ **HIGH** finding (`Confidence.HIGH`) | **41** | `MODERATE` |
| $\ge 1$ **CRITICAL** finding (`Confidence.HIGH`) | **61** | `HIGH` |
| $\ge 2$ **CRITICAL** findings (`Confidence.HIGH`) | **81** | `VERY_HIGH` |

#### Permitted Severity Floor Named Triggers:
1. **Hardcoded Credentials**: `ENT-LOG-002` with confidence $\ge 0.8$.
2. **Unprotected Mutating Admin Endpoints**: `ENT-AUTH-001` on `POST/PUT/DELETE/PATCH` routes matching `/admin/*`, `/manage/*`, or `/internal/*`.
3. **Confirmed Injection Sinks**: `ENT-INPUT-003` or `ENT-INPUT-JS-001` (raw SQL or subprocess sinks).

$$\text{Final Score} = \max(\text{Score}_{\text{density}}, \text{Severity Floor})$$

The severity floor strictly elevates the headline score; it **never lowers it**. Pure density score is always preserved in telemetry as `score_density`.

---

### Step 5: Dynamic Weight Normalization

When a repository contains pure utility libraries without web frameworks, Authentication and Authorization are marked `NOT_ANALYZED`.

To avoid diluting the score with dummy zero scores, Entropy dynamically normalizes the relative weights ($w_c^{\text{rel}}$) across the subset of active analyzed categories ($\mathcal{A}$):

$$w_c^{\text{rel}} = \frac{W_c}{\sum_{a \in \mathcal{A}} W_a}$$

$$\text{Overall Entropy Score} = \text{round}\left(\sum_{c \in \mathcal{A}} w_c^{\text{rel}} \times \text{Category Score}_c\right)$$

All scores are clamped strictly to $[0, 100]$:
- Scores $< 0 \implies 0$
- Scores $> 100 \implies 100$

---

## 8. Stage 7 & 8: Policy Engine, CI/CD, Baselines & Advisory AI

### 8.1 Delta Baselines & Lifecycle Tracking
*Code location: `backend/app/comparison/service.py`*

When comparing a pull request scan against the `main` branch baseline, findings are partitioned by their SHA-256 fingerprint:
- **`NEW`**: Fingerprint present in PR scan, absent in baseline.
- **`RESOLVED`**: Fingerprint present in baseline, absent in PR scan.
- **`PERSISTENT`**: Fingerprint present in both scans.

### 8.2 Policy Engine (`.entropy-policy.yaml`)
*Code location: `backend/app/policy/evaluator.py`*

Teams define quality gates in `.entropy-policy.yaml`:

```yaml
version: "1.0"
fail_on_tier: HIGH            # Fails CI if score >= 61
fail_on_new_critical: true   # Fails CI if any new CRITICAL finding is introduced
max_score_delta: 0.0          # PR must not increase overall architectural debt
```

The evaluator runs deterministically and exits with code `0` (Pass) or `1` (Fail) in GitHub Actions.

### 8.3 OASIS SARIF 2.1.0 Export
*Code location: `backend/app/sarif/formatter.py`*

Entropy outputs standardized SARIF 2.1.0 reports (`entropy scan . --format sarif > results.sarif`). When uploaded via `github/codeql-action/upload-sarif`, findings appear natively inside the GitHub Pull Request "Files Changed" tab with inline annotations.

### 8.4 Advisory AI Explanations & Secret Redaction
*Code location: `backend/app/ai/`*

Entropy integrates Google Gemini as a **strictly read-only advisory layer**:
- AI **never** computes scores or generates findings.
- **Redaction Pipeline (`redaction.py`)**: Before code snippets are sent to Gemini, regex filters scrub:
  - Private key blocks (`-----BEGIN RSA PRIVATE KEY-----`)
  - Cloud provider tokens (`AKIA...`, `sk_live_...`, `ghp_...`)
  - Sensitive variable assignments (`API_KEY = "..."`, `password = "..."`)
- Returns architectural rationale, long-term maintenance hazards, and refactored before/after code diffs.

---

## 9. Summary Table: Component Architecture

| Component | Technology | Primary Function | Invariant Enforced |
| :--- | :--- | :--- | :--- |
| **Ingestion** | `pathspec` + Python I/O | Safe file walk & `.gitignore` resolution | Zero code execution; excludes tests/mocks |
| **Python Parsing** | Python `ast` stdlib | Compiler AST visitor | Fault-tolerant syntax recovery |
| **JS/TS Parsing** | Recursive CST visitor | Route & middleware graph extraction | Registration ordering & pass-through filter |
| **Analyzers** | Modular `BaseAnalyzer` | 7 category pattern detection | Real AST evidence; line & snippet tracking |
| **Fingerprinting** | SHA-256 | Unique finding identity | Line-drift invariant tracking across commits |
| **Scoring Engine** | Mathematical density model | 0–100 Debt Score calculation | Deterministic, scale-invariant, anti-dilution |
| **Policy Engine** | YAML Config Evaluator | CI/CD build break decisions | 100% deterministic gatekeeping |
| **Advisory AI** | Google Gemini + Redaction | Remediations & refactoring diffs | Read-only; strict secret redaction |
| **Presentation** | Next.js 14 + Tailwind CSS | Interactive security dashboard | Pure consumer; never recalculates scores |

---

*This document serves as the authoritative architectural specification for Entropy. For questions or contributions, consult [docs/CONSTITUTION.md](CONSTITUTION.md) or open an issue on GitHub.*

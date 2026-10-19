# Entropy Scoring Specification

**Authoritative Specification for the Deterministic Entropy Scoring Engine**

> [!IMPORTANT]
> **Core Principle & Non-Goals**  
> **"The Entropy Score is an indicator of architectural/security debt detected by Entropy's static-analysis rules. It is not a vulnerability probability and does not measure AI authorship."**  
> The score MUST NOT represent:
> - Probability of exploitation
> - Probability of a live vulnerability
> - Probability that code was AI-generated
> - Percentage of AI-generated code
> - Prediction of future vulnerabilities

---

## 1. Score Range & Product Interpretation

The **Entropy Debt Score** ranges from **0 to 100**, where 0 indicates zero detected architectural/security debt and 100 indicates severe accumulated debt.

Scores are partitioned into five official tiers with explicit boundary definitions:

| Score Range | Debt Tier | Product Interpretation |
| :---: | :---: | :--- |
| **0 – 20** | `VERY_LOW` | Pristine or near-pristine codebase; highly consistent architecture and security practices. |
| **21 – 40** | `LOW` | Minor structural duplication or localized inconsistent error handling. |
| **41 – 60** | `MODERATE` | Noticeable accumulation of debt; unauthenticated administrative routes or architectural patterns need attention. |
| **61 – 80** | `HIGH` | Substantial fragmentation, swallowed errors, or missing security boundaries across critical flows. |
| **81 – 100** | `VERY_HIGH` | Severe architectural risk; elevated probability of hidden failures, leaks, or wide-open attack surfaces. |

### Clamping & Validity Guarantees
- The API and engine guarantee that all scores are strictly clamped to integer range `[0, 100]`.
- Values `< 0` clamp to `0` (`VERY_LOW`).
- Values `> 100` clamp to `100` (`VERY_HIGH`).
- Boundary transitions (`20 -> 21`, `40 -> 41`, `60 -> 61`, `80 -> 81`) are deterministically verified in unit test suites.

---

## 2. Centralized Severity Weights & Confidence Multipliers

Scoring weights are centralized in [`backend/app/scoring/weights.py`](../backend/app/scoring/weights.py) to eliminate magic numbers:

### A. Severity Weights ($W_{\text{severity}}$)
Reflects the architectural degradation hazard of the defect:

| Severity | Weight | Architectural & Security Rationale |
| :--- | :---: | :--- |
| **`CRITICAL`** | `10.0` | System signal hijacking, unauthenticated state-mutating sensitive routes (POST/DELETE/PUT/PATCH admin/payment/user). |
| **`HIGH`** | `7.0` | Silently swallowed exceptions (`ENT-ERR-004`), unauthenticated read sensitive routes (GET admin/export/token). |
| **`MEDIUM`** | `4.0` | Broad catch blocks (`ENT-ERR-002`), bare except clauses (`ENT-ERR-001`), empty handlers (`ENT-ERR-003`), standard unprotected routes. |
| **`LOW`** | `1.0` | Generic falsy fallback returns (`ENT-ERR-005`), minor boilerplate duplication. |
| **`INFO`** | `0.0` | Informational notice; does not penalize score. |

### B. Confidence Multipliers ($M_{\text{confidence}}$)
Scales severity points by detection certainty, preventing low-confidence heuristics from dominating:

| Confidence | Multiplier | Meaning |
| :--- | :---: | :--- |
| **`HIGH`** | `1.0` | 100% deterministic AST match or verified framework route taint. |
| **`MEDIUM`** | `0.8` | Structural pattern match with contextual filtering. |
| **`LOW`** | `0.5` | Broad heuristic or dampening factor. |

---

## 3. Scale-Aware Density Normalization Model

To prevent repository size from distorting scores and ensure scale invariance:
- A defect density of 1 MEDIUM defect per 100 LOC yields approximately the same score whether in a 500-line microservice or a 500,000-line monorepo.
- Monotonicity: adding any authentic finding strictly increases (or preserves) the score.
- A minimum LOC floor ($\text{MIN\_LOC\_FLOOR} = 200$) protects tiny repositories from mathematical score explosion.

### Step 1: Raw Category Penalty
For each finding $f$ in category $c$:
$$\text{Points}(f) = W_{\text{severity}}(f) \times M_{\text{confidence}}(f)$$
$$\text{Raw Penalty}_c = \sum_{f \in \text{Findings}_c} \text{Points}(f)$$

### Step 2: Codebase Scale in KLOC with Minimum Floor
$$\text{Effective LOC} = \max(\text{total\_loc}, 200)$$
$$\text{KLOC} = \frac{\text{Effective LOC}}{1000.0}$$

### Step 3: Weighted Debt Density (pts / KLOC)
$$\text{Weighted Debt Density}_c = \frac{\text{Raw Penalty}_c}{\text{KLOC}}$$

### Step 4: Asymptotic Category Saturation (0–100)
To ensure the category score is strictly bounded and asymptotic, a saturating exponential curve with saturation constant $K = 40.0$ (`DENSITY_SATURATION_FACTOR`) is applied to the density:
$$\text{Category Score}_c = 100.0 \times \left( 1.0 - e^{-\frac{\text{Weighted Debt Density}_c}{40.0}} \right)$$

### Step 5: Severity Floor Protection (High-Impact Defect Guarantees)
While defect density provides scale invariance for widespread architectural debt, critical isolated defects (such as a hardcoded production credential `DB_PASSWORD` or unauthenticated admin state-mutating endpoints) must never be diluted to zero in large repositories.

To guarantee that severe findings visibly impact the headline score regardless of repository size:
- **High-Severity Floor**: Any finding with `Severity.HIGH` and `Confidence.HIGH` establishes a minimum overall tier of `MODERATE` ($\text{Score} \ge 41$).
- **Critical-Severity Floor**: Any finding with `Severity.CRITICAL` and `Confidence.HIGH` establishes a minimum overall tier of `HIGH` ($\text{Score} \ge 61$).
- **Multiple Critical Floor**: Two or more findings ($\ge 2$) with `Severity.CRITICAL` and `Confidence.HIGH` establish a minimum overall tier of `VERY_HIGH` ($\text{Score} \ge 81$).

$$\text{Final Entropy Score} = \max(\text{Score}_{\text{density}}, \text{Severity Floor})$$

The floor is applied strictly on top of the density score and **never lowers it**. In repositories without high or critical findings, pure density invariance holds across all codebase scales.

### Mathematical Guarantees
1. **Density Invariance**: At constant defect density $\frac{\text{Raw Penalty}}{\text{KLOC}} = \rho$ without severe floor triggers, $\text{Category Score} = 100 \times (1 - e^{-\rho / 40.0})$ is strictly constant for any $\text{total\_loc} \ge 200$.
2. **Severity Lower Bound**: Critical security boundaries and credentials cannot be hidden by padding a codebase with thousands of benign lines.
3. **Scale Floor**: In tiny repositories ($\text{LOC} < 200$), the floor prevents division by near-zero.
4. **Monotonicity**: Adding any authentic debt finding $\Delta P > 0$ strictly increases or preserves $\text{Score}_{\text{density}}$ and $\text{Severity Floor}$, ensuring the overall score never decreases.

---

## 4. Category Handling: Analyzed vs. Not Analyzed & Language Coverage

> [!CAUTION]
> **Data Integrity Rule**: Categories without implemented static analyzers or lacking supported language files in the scanned codebase must NEVER receive fabricated scores or dummy findings.

The Entropy engine includes 7 distinct debt categories:

| Category | Category Identifier | Weight ($W_c$) | Supported Languages | Scoring Behavior |
| :--- | :--- | :---: | :--- | :--- |
| **Error Handling Debt** | `error_handling` | `0.15` | Python, JavaScript, TypeScript | Calculated from AST findings; Score $\in [0, 100]$. |
| **Authentication Consistency** | `authentication_consistency` | `0.20` | Python, JavaScript, TypeScript | Unprotected endpoints, inconsistency, duplicate auth. |
| **Authorization Consistency** | `authorization_consistency` | `0.20` | Python, JavaScript, TypeScript | Missing role/permission checks, inconsistent policies. |
| **Input Validation Debt** | `input_validation` | `0.15` | Python, JavaScript, TypeScript | Unvalidated request parameters reaching sensitive sinks. |
| **Logging & Secrets Debt** | `logging_and_secrets` | `0.15` | Python, JavaScript, TypeScript | Hardcoded credentials, insecure logging, missing audit trails. |
| **Architectural Consistency** | `architectural_consistency` | `0.10` | Python, JavaScript, TypeScript | Layering violations, circular module imports. |
| **Code Duplication / Boilerplate** | `code_duplication` | `0.05` | Python, JavaScript, TypeScript | Repeated structural boilerplate and duplicated routines. |

### Zero Findings vs. Not Analyzed
- **Analyzed (Zero Findings)**: The category analyzer executed against repository files in supported languages and found 0 issues. Status is `"analyzed"`, score is `0.0`.
- **Not Analyzed**: The repository does not contain files in the languages supported by the category analyzer. Status is `"not_analyzed"`, score is `null` (`None`), and the category is excluded from weight normalization.

### Partial Coverage & Status
- If either **Authentication Consistency** or **Authorization Consistency** is marked `NOT_ANALYZED` (e.g. in a repository written in an unsupported language like Go or Ruby), the overall result `status` is set to `PARTIAL`.
- The CLI, API, and frontend surface this as **"Partial Coverage"** to guarantee that unanalyzed security categories are never misrepresented as clean.

---

## 5. Overall Entropy Score Aggregation

The overall score is derived **exclusively from analyzed categories** by dynamically normalizing active weights:

Let $\mathcal{A}$ be the set of analyzed categories:
$$W_{\mathcal{A}} = \sum_{c \in \mathcal{A}} W_c$$

For each $c \in \mathcal{A}$, its effective relative weight is:
$$w_c^{\text{rel}} = \frac{W_c}{W_{\mathcal{A}}}$$

$$\text{Entropy Score} = \text{clamp}\left( \text{round}\left( \sum_{c \in \mathcal{A}} w_c^{\text{rel}} \times \text{Category Score}_c \right) \right)$$

If $\mathcal{A} = \emptyset$ (no categories could be analyzed), the overall score is `0` with status `NOT_APPLICABLE` or `PARTIAL`.

---

## 6. Score Reproducibility & Auditability

- **No Randomness**: No timestamps, UUIDs, or random seeds are used during score calculation.
- **Finding Order Invariant**: Finding lists are grouped and summed commutatively; permutation of findings produces identical scores.
- **Audit Trail**: Every result returns an `audit_trail` array documenting every intermediate calculation step for full developer auditability.

---

## 7. Regression Smoke-Test Corpus

To provide sanity checks during development, an 8-file corpus of pinned open-source code snippets is maintained under `backend/tests/calibration/corpus/` (`manifest.json`). This corpus serves strictly as a fast regression smoke test to verify basic scoring dynamics (clean snippets score near 0; vulnerable snippets trigger detections and severity floors).

> [!NOTE]
> **Status: Experimental**: The 8-file corpus is a regression smoke test and does not constitute full-scale real-world calibration. Real-world full-repository calibration and validation across production codebases is covered separately.

### A. Smoke-Test Corpus Table

The table below reflects scans executed across the 8 smoke-test snippets:

| Project Snippet | Ecosystem | Type | LOC | Findings by Category | Score | Tier | Severity Floor Applied |
| :--- | :--- | :---: | :---: | :--- | :---: | :---: | :---: |
| **express-auth-clean** (`expressjs/express`) | JavaScript | Clean | 134 | 0 | **0 / 100** | `VERY_LOW` | No |
| **fastapi-security-clean** (`fastapi/fastapi`) | Python | Clean | 30 | 0 | **0 / 100** | `VERY_LOW` | No |
| **vulnerable-flask** (`we45/Vulnerable-Flask-App`) | Python | Vulnerable | 339 | 19 AuthN, 1 AuthZ, 1 Input | **81 / 100** | `VERY_HIGH` | Yes (CRITICAL findings) |
| **dvna-vulnerable** (`appsecco/dvna`) | JavaScript | Vulnerable | 488 | 2 AuthZ, 3 Input | **41 / 100** | `MODERATE` | Yes (HIGH findings) |
| **fastapi-clean-oauth2** (`fastapi/fastapi`) | Python | Clean | 11 | 0 | **0 / 100** | `VERY_LOW` | No |
| **nestjs-auth-clean** (`nestjs/nest`) | TypeScript | Clean | 28 | 0 | **0 / 100** | `VERY_LOW` | No |
| **hackable-flask-vulnerable** (`JasonHinds13/hackable`) | Python | Vulnerable | 95 | 2 AuthN, 3 Input | **41 / 100** | `MODERATE` | Yes (HIGH findings) |
| **juice-shop-vulnerable** (`juice-shop/juice-shop`) | TypeScript | Vulnerable | 1,062 | 3 AuthZ | **61 / 100** | `HIGH` | Yes (CRITICAL findings) |

### B. Regression Smoke Test Expectations
- **Smoke-Test Clean Snippets**: Score near 0 with `VERY_LOW` debt.
- **Smoke-Test Vulnerable Snippets**: Flag expected high-severity and critical patterns, activating the severity floor where appropriate.

### C. Regression Monotonicity Fixtures
The small, hand-written fixtures under `backend/tests/calibration/fixtures/` (`test_calibration_ordering.py`) are preserved exclusively as fast unit-level regression sanity checks (asserting that synthetic clean < messy < insecure), but do not serve as authoritative empirical calibration.


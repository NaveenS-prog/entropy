# Entropy Scoring Specification

**Authoritative Specification for the Deterministic Entropy Scoring Engine (Phase 4)**

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

The **Entropy Debt Score** ranges from **0 to 100**, where 0 indicates zero detected architectural debt and 100 indicates severe accumulated debt.

Scores are partitioned into five official tiers with explicit boundary definitions:

| Score Range | Debt Tier | Product Interpretation |
| :---: | :---: | :--- |
| **0 – 20** | `VERY_LOW` | Pristine or near-pristine codebase; highly consistent architecture. |
| **21 – 40** | `LOW` | Minor structural duplication or localized inconsistent error handling. |
| **41 – 60** | `MODERATE` | Noticeable accumulation of silent debt; architectural patterns need attention. |
| **61 – 80** | `HIGH` | Substantial fragmentation, swallowed errors, or missing security boundaries. |
| **81 – 100** | `VERY_HIGH` | Severe architectural risk; elevated probability of hidden failures and bugs. |

### Clamping & Validity Guarantees
- The API and engine guarantee that all scores are strictly clamped to integer range `[0, 100]`.
- Values `< 0` clamp to `0` (`VERY_LOW`).
- Values `> 100` clamp to `100` (`VERY_HIGH`).
- Boundary transitions (`20 -> 21`, `40 -> 41`, `60 -> 61`, `80 -> 81`) are deterministically verified in unit test suites.

---

## 2. Centralized Severity Weights & Confidence Multipliers

Scoring weights are centralized in [`app/scoring/weights.py`](file:///home/naveen/silentguard/backend/app/scoring/weights.py) to eliminate magic numbers:

### A. Severity Weights ($W_{\text{severity}}$)
Reflects the architectural degradation hazard of the defect:

| Severity | Weight | Architectural Rationale |
| :--- | :---: | :--- |
| **`CRITICAL`** | `10.0` | System signal hijacking, catastrophic architectural degradation. |
| **`HIGH`** | `7.0` | Silently swallowed exceptions (`ENT-ERR-004`) without logging or re-raise. |
| **`MEDIUM`** | `4.0` | Broad catch blocks (`ENT-ERR-002`), bare except clauses (`ENT-ERR-001`), empty handlers (`ENT-ERR-003`). |
| **`LOW`** | `1.0` | Generic falsy fallback returns (`ENT-ERR-005`). |
| **`INFO`** | `0.0` | Informational notice; does not penalize score. |

### B. Confidence Multipliers ($M_{\text{confidence}}$)
Scales severity points by detection certainty, preventing low-confidence heuristics from dominating:

| Confidence | Multiplier | Meaning |
| :--- | :---: | :--- |
| **`HIGH`** | `1.0` | 100% deterministic AST match. |
| **`MEDIUM`** | `0.8` | Structural pattern match with contextual filtering. |
| **`LOW`** | `0.5` | Broad heuristic or dampening factor. |

---

## 3. Scale-Aware Normalization Model

To prevent repository size from producing misleading scores:
- A tiny 100-line script with 10 swallowed exceptions exhibits extreme debt density.
- A 500,000-line enterprise monorepo with 10 swallowed exceptions exhibits localized debt.
- A static analysis score must remain scale-resistant while preserving mathematical monotonicity.

### Step 1: Raw Category Penalty
For each finding $f$ in category $c$:
$$\text{Points}(f) = W_{\text{severity}}(f) \times M_{\text{confidence}}(f)$$
$$\text{Raw Penalty}_c = \sum_{f \in \text{Findings}_c} \text{Points}(f)$$

### Step 2: Sublinear Scale Damping Factor ($S$)
Let $\text{LOC} = \max(\text{total\_loc}, 100)$:
$$S = \max\left(1.0, \sqrt{\frac{\text{LOC}}{500}}\right)$$

### Step 3: Normalized Category Penalty
$$\text{Normalized Penalty}_c = \frac{\text{Raw Penalty}_c}{S}$$

### Step 4: Asymptotic Category Saturation (0–100)
To ensure the category score is strictly bounded and smooth, an asymptotic curve with saturation constant $K = 25.0$ is applied:
$$\text{Category Score}_c = 100.0 \times \left( 1.0 - e^{-\frac{\text{Normalized Penalty}_c}{25.0}} \right)$$

### Mathematical Monotonicity Guarantee
For any fixed codebase size $\text{LOC}$, adding any authentic debt finding $\Delta P > 0$ strictly increases $\text{Raw Penalty}$, which increases $\text{Normalized Penalty}$, which strictly increases $\text{Category Score}$. The score is guaranteed to be monotonically non-decreasing.

---

## 4. Category Handling: Analyzed vs. Not Analyzed

> [!CAUTION]
> **Data Integrity Rule**: Categories without implemented static analyzers must NEVER receive fabricated scores or dummy findings.

| Category | Phase 4 Status | Weight ($W_c$) | Scoring Behavior |
| :--- | :---: | :---: | :--- |
| **Error Handling Debt** | `ANALYZED` | `0.15` | Calculated from Phase 3 AST findings. Score $\in [0, 100]$. |
| **Authentication Consistency** | `NOT_ANALYZED` | `0.20` | Scheduled for future phase. Score is `None`. Finding count `0`. |
| **Authorization Consistency** | `NOT_ANALYZED` | `0.20` | Scheduled for future phase. Score is `None`. Finding count `0`. |
| **Input Validation Debt** | `NOT_ANALYZED` | `0.15` | Scheduled for future phase. Score is `None`. Finding count `0`. |
| **Logging & Secrets Debt** | `NOT_ANALYZED` | `0.15` | Scheduled for future phase. Score is `None`. Finding count `0`. |
| **Architectural Consistency** | `NOT_ANALYZED` | `0.10` | Scheduled for future phase. Score is `None`. Finding count `0`. |
| **Code Duplication / Boilerplate** | `NOT_ANALYZED` | `0.05` | Scheduled for future phase. Score is `None`. Finding count `0`. |

### Zero Findings vs. Not Analyzed
- **Zero Findings**: Category has an active analyzer, analyzed the files, and detected 0 issues. Status is `"analyzed"`, score is `0.0`.
- **Not Analyzed**: Category does not yet have an analyzer. Status is `"not_analyzed"`, score is `null` (`None`).

---

## 5. Overall Entropy Score Aggregation

The overall score is derived **exclusively from analyzed categories** by normalizing active weights:

Let $\mathcal{A}$ be the set of analyzed categories:
$$W_{\mathcal{A}} = \sum_{c \in \mathcal{A}} W_c$$

For each $c \in \mathcal{A}$, its effective relative weight is:
$$w_c^{\text{rel}} = \frac{W_c}{W_{\mathcal{A}}}$$

$$\text{Entropy Score} = \text{clamp}\left( \text{round}\left( \sum_{c \in \mathcal{A}} w_c^{\text{rel}} \times \text{Category Score}_c \right) \right)$$

In Phase 4, $\mathcal{A} = \{\text{Error Handling Debt}\}$, so $W_{\mathcal{A}} = 0.15$ and $w_{\text{err}}^{\text{rel}} = 1.0$. The overall score accurately reflects the analyzed error handling debt.

---

## 6. Score Reproducibility & Auditability

- **No Randomness**: No timestamps, UUIDs, or random seeds are used during score calculation.
- **Finding Order Invariant**: Finding lists are grouped and summed commutatively; permutation of findings produces identical scores.
- **Audit Trail**: Every result returns an `audit_trail` array documenting every intermediate calculation step for full developer auditability.

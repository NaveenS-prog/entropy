# SilentGuard Scoring Specification

## 1. Score Range & Product Interpretation

The **Silent Security Debt Score** ranges from **0 to 100**, where 0 indicates zero accumulated debt and 100 indicates very high accumulated debt.

These labels are product categories, not claims of active vulnerability exploitability:

| Score Range | Debt Tier | Interpretation |
| :---: | :---: | :--- |
| **0 – 20** | `VERY_LOW` | Pristine or near-pristine codebase; highly consistent architecture. |
| **21 – 40** | `LOW` | Minor structural duplication or localized inconsistent error handling. |
| **41 – 60** | `MODERATE` | Noticeable accumulation of silent debt; architectural patterns need attention. |
| **61 – 80** | `HIGH` | Substantial fragmentation, swallowed errors, or missing security boundaries. |
| **81 – 100** | `VERY_HIGH` | Severe architectural risk; elevated probability of hidden failures and bugs. |

---

## 2. Category Weighting Distribution

The 7 MVP categories are weighted according to their potential impact on security boundaries and maintenance risk:

| Debt Category | Category Weight ($W_c$) | Rationale |
| :--- | :---: | :--- |
| **Authentication Consistency** | `0.20` (20%) | Critical perimeter control; inconsistent auth creates direct bypasses. |
| **Authorization Consistency** | `0.20` (20%) | Essential access control; inconsistent roles lead to privilege escalation. |
| **Error Handling Debt** | `0.15` (15%) | Swallowed exceptions mask internal security failures and corrupt state. |
| **Input Validation Debt** | `0.15` (15%) | Fragmented validation permits malformed payloads across services. |
| **Logging & Secrets Debt** | `0.15` (15%) | Missing audit trails and hardcoded secret patterns prevent incident response. |
| **Architectural Consistency** | `0.10` (10%) | Boundary violations between data layers and API surfaces. |
| **Code Duplication / Boilerplate** | `0.05` (5%) | Copy-pasted logic creates diverging bug fixes and synchronization debt. |
| **Total** | `1.00` (100%) | Full coverage of Silent Security Debt. |

---

## 3. Mathematical Formula

### Step 1: Raw Category Penalty
For each finding $f$ in category $c$, calculate its effective penalty points:

$$\text{Points}(f) = \text{SeverityWeight}(\text{severity}_f) \times \text{ConfidenceMultiplier}(\text{confidence}_f)$$

#### Severity Weights:
- `CRITICAL`: 10.0 pts
- `HIGH`: 5.0 pts
- `MEDIUM`: 2.5 pts
- `LOW`: 1.0 pts
- `INFO`: 0.25 pts

#### Confidence Multipliers:
- `HIGH`: 1.0
- `MEDIUM`: 0.8
- `LOW`: 0.5

$$\text{RawPenalty}_c = \sum_{f \in \text{Findings}_c} \text{Points}(f)$$

### Step 2: Asymptotic Category Normalization (0–100)
To prevent a high count of minor issues from causing unbounded score explosions, each category score is normalized using a smooth asymptotic saturation curve with parameter $K = 20.0$:

$$\text{CategoryScore}_c = 100 \times \left( 1 - e^{-\frac{\text{RawPenalty}_c}{K}} \right)$$

- When $\text{RawPenalty}_c = 0$, $\text{CategoryScore}_c = 0.0$
- When $\text{RawPenalty}_c = 5.0$ (e.g. 1 High finding), $\text{CategoryScore}_c \approx 22.1$
- When $\text{RawPenalty}_c = 10.0$ (e.g. 2 High findings), $\text{CategoryScore}_c \approx 39.3$
- When $\text{RawPenalty}_c = 20.0$ (e.g. 2 Critical findings), $\text{CategoryScore}_c \approx 63.2$
- When $\text{RawPenalty}_c \ge 40.0$, $\text{CategoryScore}_c \to 86 - 100$

### Step 3: Total Weighted Score
The overall score is the weighted sum of all category scores rounded to the nearest integer:

$$\text{Total Score} = \text{Round}\left( \sum_{c \in \text{Categories}} \text{CategoryScore}_c \times W_c \right)$$

---

## 4. Auditability & Grounding Invariant

Every scan result produces an `audit_trail` list of strings explaining the exact mathematical derivation of every number. No black-box magic numbers are permitted.

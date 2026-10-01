# The SilentGuard Engineering Constitution

## Preamble

SilentGuard is built to surface **Silent Security Debt** in modern software repositories. Because the platform operates in the sensitive domain of cybersecurity and developer trust, the engineering team adheres to this binding Constitution.

---

## Article I: Product Definition & Boundaries

### 1.1 Silent Security Debt Defined
Traditional application security tools scan for active vulnerabilities present in code today (such as SQL injections or buffer overflows). SilentGuard identifies:

> **Observable architectural patterns that may not represent an immediate vulnerability today, but accumulate security and maintenance risk over time.**

Examples of Silent Security Debt include:
- Swallowed or overly broad exception handlers masking authentication/crypto errors.
- Inconsistent authorization and authentication checks across endpoints.
- Fragmented or repeated validation logic across service layers.
- Inconsistent logging, missing audit logs, and insecure secret-handling patterns.
- Boilerplate duplication and repeated structural patterns across codebase silos.

### 1.2 The Non-Attribution Covenant (Anti-Hallucination)
- **Rule 1**: SilentGuard must **NEVER** claim: *"This code was written by AI."*
- **Rule 2**: The product must never present uncertain AI authorship as a fact.
- **Rule 3**: Instead, identify: *"AI-assisted development patterns / generated-code-like structural patterns / architectural inconsistencies."*
- **Rule 4**: Findings must be based exclusively on **measurable, observable properties**:
  - Structural duplication
  - Repeated boilerplate
  - Repeated AST structures
  - Inconsistent implementation strategies
  - Inconsistent security controls
  - Fragmented validation patterns

---

## Article II: The 10 Inviolable Engineering Rules

1. **No Mock Security Findings**: Every finding must originate from real AST syntax in scanned source files.
2. **No Fake Scan Results**: Never return canned or hardcoded scan responses. An empty codebase produces zero findings.
3. **No Hardcoded Dashboard Metrics**: Every number, percentage, and badge displayed in the user interface must be computed directly by the backend scoring engine.
4. **No Pretending an Analyzer Exists**: If an analyzer is not implemented, its category score is reported as 0.0 with transparent telemetry that no rules were active.
5. **Backend is the Source of Truth**: The frontend is purely a presentation layer. The frontend must **never** calculate or recalculate security debt scores.
6. **Every Score Must Be Explainable**: The scoring engine must generate a step-by-step mathematical audit trail detailing raw penalties, confidence factors, and weights.
7. **Prefer Deterministic Static Analysis Over LLM Guesses**: Static syntax inspection produces findings; LLMs do not invent findings.
8. **AI Explains Findings, Not Invents Them**: The AI layer provides contextual architectural explanations and suggested refactoring diffs grounded in static analysis evidence.
9. **Fail Gracefully on Parse Errors**: When a file contains syntax errors or unsupported constructs, record a non-fatal warning and continue scanning the rest of the repository.
10. **Preserve Exact Source Locations**: Every finding must capture the exact file path, starting line, ending line, and surrounding verbatim code snippet.

---

## Article III: Architectural Invariants

- **Separation of Concerns**: Static analysis rules must never be placed inside API route handlers or frontend components.
- **Zero Hallucination Policy**: If an analysis rule cannot be proven with AST verification, it must not be shipped to production.
- **Minimal Dependencies**: The backend core must rely on standard, well-maintained libraries (FastAPI, Pydantic, Python AST) avoiding brittle or bloated dependencies.

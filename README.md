# Entropy

### Architectural Security Debt Analyzer for AI-Assisted Codebases

Entropy is an architectural security-debt analyzer for AI-assisted codebases. It identifies structural and architectural patterns that accumulate hidden maintenance and security risk over time.

Entropy does **NOT** claim to detect whether code was written by AI. Instead, Entropy analyzes observable codebase structure and architectural patterns deterministically without executing repository code.

---

## The Non-Attribution Covenant

Entropy adheres strictly to the **Non-Attribution Covenant** defined in the **[Engineering Constitution](docs/CONSTITUTION.md)**:

> **"The Entropy Score is an indicator of architectural and security debt detected by Entropy's static-analysis rules. It is not a vulnerability probability and does not measure AI authorship."**

Entropy will never:
- Claim code was written by an AI or a human.
- Compute an "AI probability" or "authorship percentage".
- Attribute defects to author identity or generation tooling.

All measurements reflect concrete, verifiable AST patterns: swallowed exceptions, missing security boundaries, unvalidated input flows, and structural duplication.

---

## How to Read the Score

The **Entropy Debt Score** is a deterministic scale from **0 to 100**, where 0 indicates zero detected architectural/security debt and 100 indicates severe accumulated debt.

### Risk Tiers
- **`0 – 20` (Very Low)**: Pristine or near-pristine codebase; consistent security and error handling.
- **`21 – 40` (Low)**: Minor structural duplication or localized inconsistencies.
- **`41 – 60` (Moderate)**: Noticeable accumulation of debt; unauthenticated administrative routes or architectural patterns need attention.
- **`61 – 80` (High)**: Substantial fragmentation, swallowed errors, or missing security boundaries across critical flows.
- **`81 – 100` (Very High)**: Severe architectural risk; elevated probability of hidden failures, leaks, or wide-open attack surfaces.

### Density-Based Scoring
Entropy uses **weighted defect density per 1,000 lines of code (KLOC)** combined with an asymptotic saturation curve. This guarantees:
- **Scale Invariance**: A codebase with 1 defect per 100 LOC receives the same score whether it has 500 lines or 500,000 lines.
- **Scale Floor**: Repositories under 200 LOC use a minimum floor ($\text{MIN\_LOC\_FLOOR} = 200$) to prevent score explosion.
- **Monotonicity**: Adding any genuine finding strictly increases (or preserves) the score.

---

## Limitations

1. **Heuristic Indicator, Not Vulnerability Proof**:
   The Entropy score is a static heuristic measuring structural debt, inconsistency, and attack surface exposure. It is **not** a CVE vulnerability scanner, penetration testing tool, or runtime exploit verifier. Scores should not be compared directly against tools measuring different properties (such as DAST tools or dependency CVE counts).
2. **Supported Languages**:
   | Analyzer Category | Supported Languages | Supported Frameworks |
   | :--- | :--- | :--- |
   | **Error Handling** | Python, JavaScript, TypeScript | Standard AST syntax |
   | **Authentication Consistency** | Python, JavaScript, TypeScript | FastAPI, Flask, Django, Express, Fastify, Next.js |
   | **Authorization Consistency** | Python, JavaScript, TypeScript | FastAPI, Flask, Django, Express, Fastify, Next.js |
   | **Input Validation** | Python, JavaScript, TypeScript | Standard request params to sensitive sinks |
   | **Logging & Secrets** | Python, JavaScript, TypeScript | Standard logging & credential patterns |
   | **Architectural Consistency** | Python, JavaScript, TypeScript | Import dependencies, layering |
   | **Code Duplication** | Python, JavaScript, TypeScript | Subtree fingerprinting |

   *Languages not listed above (e.g., Go, Rust, Java, C++) are not currently analyzed by the rule engine.*
3. **Partial Coverage Transparency**:
   When scanning a repository containing files in unsupported languages, unanalyzed categories receive a status of `NOT_ANALYZED` with a `null` score, and are excluded from weight calculation. If **Authentication** or **Authorization** cannot be analyzed, the overall result status is explicitly marked **`PARTIAL`** ("Partial Coverage") to guarantee that missing analyzer coverage is never mistaken for a clean codebase.

---

## API Security & Configuration

Entropy provides built-in enterprise API security controls configured via environment variables:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `ENTROPY_API_KEY` | *(None)* | Secret API key. When set, all `/api/v1` routes (except `/health` and HMAC-validated GitHub webhooks) require the `X-API-Key` header. When unset, requests are restricted to `localhost` (`127.0.0.1`, `::1`). |
| `SCAN_ALLOWED_ROOTS` | `["."]` | Whitelist of directory paths permitted for local repository scans. Any target path resolving outside these roots returns a `400 Bad Request` (`SECURITY_VIOLATION`). |
| `ENTROPY_AI_PROVIDER` | `gemini` | AI reasoning provider. Keys are transmitted via `x-goog-api-key` headers and never leaked in URLs or logs. |

> **CLI Note**: The CLI runs locally as the invoking user and operates with the user's local filesystem permissions. For automated server deployments, `SCAN_ALLOWED_ROOTS` enforces strict filesystem isolation.

---

## Sample CLI & JSON Output

### Running a Scan via CLI
```bash
entropy scan .
```

### CLI Terminal Output
```
Entropy Scan
────────────────────────────────────────
Repository: /path/to/project
Status: AVAILABLE (Full Coverage)

Files discovered: 42
Files analyzed:   38
Lines of code:    4,250
Findings:         12

Entropy Score: 28 / 100
Band: Low

Categories:
  Authentication Consistency    42.1 (MODERATE)
  Authorization Consistency     35.0 (LOW)
  Error Handling Debt           21.5 (LOW)
  Input Validation Debt         18.2 (VERY_LOW)
  Logging & Secrets Debt        12.0 (VERY_LOW)
  Architectural Consistency      5.0 (VERY_LOW)
  Code Duplication / Boilerplate 0.0 (VERY_LOW)
```

### JSON Output (`--json` or `POST /api/v1/scans`)
```json
{
  "scan_id": "scan_8df7a19c",
  "repository": {
    "name": "my-service",
    "total_loc": 4250,
    "languages": ["python", "javascript"]
  },
  "score": {
    "total_score": 28,
    "tier": "LOW",
    "status": "AVAILABLE",
    "coverage": {
      "percentage_covered": 100.0,
      "uncovered_loc": 0,
      "supported_languages": ["python", "javascript", "typescript"],
      "present_languages": ["python", "javascript"],
      "categories_analyzed": [
        "error_handling",
        "authentication_consistency",
        "authorization_consistency",
        "input_validation",
        "logging_and_secrets",
        "architectural_consistency",
        "code_duplication"
      ],
      "categories_not_analyzed": []
    },
    "category_scores": {
      "authentication_consistency": 42.1,
      "authorization_consistency": 35.0,
      "error_handling": 21.5,
      "input_validation": 18.2,
      "logging_and_secrets": 12.0,
      "architectural_consistency": 5.0,
      "code_duplication": 0.0
    }
  }
}
```

---

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm

### 1. Launch Everything Locally
```bash
./scripts/dev.sh
```
- **Backend API**: [http://localhost:8000](http://localhost:8000) (Interactive Swagger Docs: [http://localhost:8000/docs](http://localhost:8000/docs))
- **Frontend Dashboard**: [http://localhost:3000](http://localhost:3000)

### 2. Run Test Suite
```bash
./scripts/test.sh
```

### 3. Run Linters & Type Checks
```bash
./scripts/lint.sh
```

---

## Documentation

- **[System Architecture (ARCHITECTURE.md)](docs/ARCHITECTURE.md)**: Architecture, parsing strategies, and multi-language engine.
- **[Engineering Constitution (CONSTITUTION.md)](docs/CONSTITUTION.md)**: Foundational tenets, non-attribution covenant, and 10 inviolable laws.
- **[Scoring Specification (SCORING_SPECIFICATION.md)](docs/SCORING_SPECIFICATION.md)**: Mathematical derivation of the density scoring model, weights, and calibration evidence.
- **[Policy Engine & CI/CD Gating (POLICY_ENGINE_AND_CI_CD.md)](docs/POLICY_ENGINE_AND_CI_CD.md)**: Policy enforcement, delta-based CI gating, and PR workflow.
- **[CLI Reference (CLI.md)](docs/CLI.md)**: Complete command-line manual and option reference.

# Entropy

### Architectural Security Debt Analyzer for AI-Assisted Codebases

Entropy is an architectural security-debt analyzer for AI-assisted codebases. It identifies structural and architectural patterns that accumulate hidden maintenance and security risk over time.

Entropy does **NOT** claim to detect whether code was written by AI. Instead, Entropy analyzes observable codebase structure and architectural patterns deterministically without executing repository code.

> [!NOTE]
> **Status**: The Entropy Debt Score is experimental and is not yet calibrated on real-world repositories. It measures statically observable structural and architectural debt patterns as a heuristic of code health, not runtime vulnerability exploitability. Full-repo real-world calibration is currently in progress.

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

2. **Analyzer Capabilities, Languages, and Frameworks**:
   | Analyzer Category | Supported Languages | Supported Frameworks & Analyzed Constructs |
   | :--- | :--- | :--- |
   | **Error Handling** | Python, JavaScript, TypeScript | Try/catch/except, empty catch blocks, swallowed errors, unhandled rejections |
   | **Authentication Consistency** | Python, JavaScript, TypeScript | **Python**: FastAPI (Depends, Security), Flask (@login_required), Django (@login_required, FBVs/CBVs)<br>**JS/TS**: Express (middleware, route guards), Fastify (hooks/preHandler), Next.js (middleware, API routes), Hono (c.get('user'), middleware), NestJS (@Controller, @UseGuards, @Public) |
   | **Authorization Consistency** | Python, JavaScript, TypeScript | **Python**: FastAPI (Scopes, role dependencies), Flask (role decorators), Django (permission checks)<br>**JS/TS**: Express (role middleware), Fastify (role hooks), Next.js (RBAC), Hono (role checks), NestJS (@Roles, @UseGuards) |
   | **Input Validation** | Python, JavaScript, TypeScript | **Python**: Pydantic schemas, raw SQL string concatenation / f-strings / %-formatting in `cursor.execute`, `session.execute(text(...))`, `db.run`<br>**JS/TS**: Zod, Joi, Yup, SQL template string / concatenation injection detection |
   | **Logging & Secrets** | Python, JavaScript, TypeScript | Secret regex patterns, high Shannon entropy string literals (>3.2), unredacted sensitive logging |
   | **Architectural Consistency** | Python, JavaScript, TypeScript | Circular module dependencies, import layer violations |
   | **Code Duplication** | Python, JavaScript, TypeScript | AST subtree fingerprinting across functions and methods |

   *Languages not listed above (e.g., Go, Rust, Java, C++) are not currently analyzed by the rule engine.*

3. **Headline Score Severity Floor**:
   To prevent severe security findings from being obscured in large repositories (where high line counts would dilute pure defect density to near 0) or diluted by clean categories in the weighted average, Entropy enforces a **Severity Floor**:
   - Any `HIGH`-severity finding with `HIGH` confidence sets a minimum overall tier of **MODERATE** (score $\ge 41$).
   - Any `CRITICAL`-severity finding with `HIGH` confidence sets a minimum overall tier of **HIGH** (score $\ge 61$).
   - Multiple `CRITICAL` findings set a minimum overall tier of **VERY_HIGH** (score $\ge 81$).
   - The floor strictly elevates the headline score and never lowers it. Pure density is always calculated and surfaced alongside as `score_density`.

4. **Middleware Analysis Limits & Realism**:
   - **Registration Ordering**: In Express/Fastify, `app.use()` and `router.use()` only protect routes registered *after* the middleware declaration. Routes declared prior to `app.use()` are evaluated without that middleware.
   - **Mount-Path Scoping**: Middleware registered with a mount path prefix (e.g., `app.use('/api', auth)`) applies exclusively to routes under `/api`.
   - **Trivial Pass-Through Inspection**: When middleware is defined in the same file, Entropy inspects its AST body. Functions that trivially call `next()` or return without inspecting headers, cookies, tokens, sessions, or `req.user` are discarded as no-op pass-throughs and do not count as authentication evidence.
   - **Imported Middleware (MEDIUM Confidence)**: When middleware is imported from external modules and cannot be AST-resolved in-file, Entropy falls back to name-based pattern matching (`auth`, `jwt`, `session`) with `Confidence.MEDIUM`. Name-only evidence is never reported as `Confidence.HIGH`.

5. **Framework Coverage & Unsupported Framework Behavior (NestJS, Koa, etc.)**:
   - **NestJS Support**: Fully supported with class-level `@Controller` prefixes, HTTP method decorators (`@Get`, `@Post`, `@Put`, `@Patch`, `@Delete`), and guard evidence (`@UseGuards`, `@Roles`, `@Public`).
   - **Unsupported Web Frameworks**: If a repository contains Python or JS/TS web code but imports an unsupported framework (e.g., Koa, Hapi, Restify, Adonis, Sails), Authentication and Authorization are marked `NOT_ANALYZED` with an explicit reason naming the framework (e.g., *"koa detected, not supported (supported: express, fastify, nextjs, hono, nestjs)"*) and overall scan status is set to **`PARTIAL`**.
   - **Pure Libraries**: Repositories containing source code but no HTTP routes report *"No HTTP routes detected; authentication/authorization analysis skipped"* rather than silently reporting a clean 0 score.

---

## API Security & Configuration

Entropy provides built-in enterprise API security controls configured via environment variables:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `ENTROPY_API_KEY` | *(None)* | Secret API key verified with constant-time comparison (`hmac.compare_digest`). When set, all `/api/v1` routes (except `/health` and HMAC-validated GitHub webhooks) require the `X-API-Key` header. |
| `ENTROPY_ALLOW_LOCALHOST_NO_KEY` | `false` (server) / `true` (CLI, `dev.sh`) | When `ENTROPY_API_KEY` is not set, enables access for localhost callers (`127.0.0.1`, `::1`). When `false`, all protected requests return `401 Unauthorized`. |
| `ENTROPY_SCAN_ALLOWED_ROOTS` | `["."]` | Whitelist of directory paths permitted for repository scanning. Accepts: (1) single plain path `/var/repos`, (2) comma-separated `/a, /b`, or (3) JSON array `'["/a", "/b"]'`. Any target path resolving outside these roots returns a `400 Bad Request` (`SECURITY_VIOLATION`) without echoing internal paths. |
| `ENTROPY_AI_PROVIDER` | `gemini` | AI reasoning provider. Keys are transmitted via `x-goog-api-key` headers and never leaked in URLs or logs. |

> [!CAUTION]
> **Reverse Proxy Boundary**: Behind a reverse proxy (e.g. Nginx, Traefik), the peer IP is the proxy itself (often `127.0.0.1`). Entropy does not read `X-Forwarded-For` for authentication decisions. In production behind a reverse proxy, you must set `ENTROPY_API_KEY` and keep `ENTROPY_ALLOW_LOCALHOST_NO_KEY=false`.

> **CLI Note**: The CLI runs locally as the invoking user and operates with the user's local filesystem permissions. For automated server deployments, `ENTROPY_SCAN_ALLOWED_ROOTS` enforces strict filesystem isolation.

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

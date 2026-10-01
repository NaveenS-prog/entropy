# Entropy

### Architectural Security Debt Analyzer for AI-Assisted Codebases

Entropy is an architectural security-debt analyzer for AI-assisted codebases. It identifies structural and architectural patterns that can accumulate hidden maintenance and security risk over time.

Entropy does **NOT** claim to detect whether code was written by AI. Instead, Entropy analyzes observable codebase structure and architectural patterns deterministically without executing repository code.

---

## The Problem: Architectural Security Debt

Traditional security scanners focus almost exclusively on active vulnerabilities present in code today (such as known CVEs or SQL injections). 

In modern software development — especially with widespread adoption of AI code generation — codebases frequently accumulate subtle architectural flaws:
- Swallowed exceptions and bare error handlers masking failures
- Inconsistent authorization or authentication checks across endpoints
- Fragmented or repeated input validation logic
- Inconsistent logging, missing audit trails, and insecure secret patterns
- Duplicated boilerplate and repeated AST structures across silos

Entropy surfaces these patterns deterministically and measures their cumulative risk.

---

## Core Engineering Principles

Entropy adheres to a strict, non-negotiable **[Engineering Constitution](docs/CONSTITUTION.md)**:

1. **No Fake Scan Results**: Zero mock data; every finding is backed by real AST syntax.
2. **Backend is Source of Truth**: The frontend never computes or modifies security scores.
3. **Every Score is Explainable**: Scores (0–100) are mathematically auditable.
4. **The Non-Attribution Covenant**: Never claim *"This code was written by AI."* Instead, measure observable structural patterns.
5. **Deterministic Static Analysis**: AST-based static parsing with zero code execution.

---

## Repository Structure

```
entropy/
├── backend/
│   ├── app/
│   │   ├── api/v1/          # Versioned REST endpoints (health, scans, analyzers, repositories)
│   │   ├── core/            # Config, logging, domain exceptions
│   │   ├── models/domain/   # Pure domain models (Finding, Rule, Score, Enums, Manifest)
│   │   ├── repository/      # File discovery, language detection, Git metadata, Manifest builder
│   │   ├── parser/          # Abstract BaseParser & resilient Python AST parser
│   │   ├── analyzers/       # AST Contexts & pluggable AnalyzerRegistry
│   │   ├── scoring/         # Deterministic 0-100 ScoringEngine & Category weights
│   │   ├── services/        # ScanService & RepositoryService coordinators
│   │   └── main.py          # FastAPI application entrypoint
│   ├── tests/               # Pytest unit and integration test suite
│   ├── pyproject.toml
│   └── ruff.toml
├── frontend/
│   ├── app/                 # Next.js 14 App Router (Dashboard, Constitution)
│   ├── components/          # FindingsViewer, ScanModal, UI components
│   ├── lib/                 # Typed API client, styling utilities
│   ├── types/               # TypeScript interfaces mirroring backend domain models
│   ├── package.json
│   └── tailwind.config.ts
├── docs/                    # Architecture, Constitution, Scoring & Analyzer specs
├── scripts/                 # dev.sh, test.sh, lint.sh
└── README.md
```

---

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm

### 1. Launch Everything Locally
Run the unified development launcher:
```bash
./scripts/dev.sh
```
This boots:
- **Backend API**: [http://localhost:8000](http://localhost:8000) (Interactive Swagger Docs: [http://localhost:8000/docs](http://localhost:8000/docs))
- **Frontend Dashboard**: [http://localhost:3000](http://localhost:3000)

### 2. Run Test Suite
```bash
./scripts/test.sh
```
Executes both:
- Backend `pytest` suite
- Frontend `vitest` suite

### 3. Run Linters & Type Checks
```bash
./scripts/lint.sh
```
Runs `ruff` on the Python codebase and `eslint` on the Next.js frontend.

---

## Documentation

- **[System Architecture (ARCHITECTURE.md)](docs/ARCHITECTURE.md)**: Deep dive into the decoupled architecture, parsing strategies, and multi-language roadmap.
- **[Engineering Constitution (CONSTITUTION.md)](docs/CONSTITUTION.md)**: The foundational tenets, non-attribution rules, and 10 inviolable laws.
- **[Scoring Specification (SCORING_SPECIFICATION.md)](docs/SCORING_SPECIFICATION.md)**: Mathematical derivation of the Architectural Security Debt Score and category weights.
- **[Analyzer Authoring Guide (ANALYZER_SPECIFICATION.md)](docs/ANALYZER_SPECIFICATION.md)**: How to write, register, and test modular static analysis rules.

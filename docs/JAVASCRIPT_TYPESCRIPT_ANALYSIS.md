# Phase 11 — JavaScript & TypeScript Static Analysis Engine

## Overview

The **JavaScript & TypeScript Static Analysis Engine** is Entropy's Phase 11 multi-language extension. It equips the platform with native, deterministic static analysis for the modern JavaScript and TypeScript ecosystem while strictly upholding Entropy's non-negotiable security and reliability invariants.

### Core Security Principle: Zero Code Execution

> **Entropy performs 100% static analysis through abstract syntax tree (AST) parsing. At NO point does Entropy run `node`, `npm`, `npx`, `bun`, `deno`, `import`, or `eval` on repository files. Malicious scripts, obfuscated payloads, environment variable scrapers, and Canary execution bombs embedded in source code are completely inert.**

---

## 1. Supported Languages & File Extensions

Entropy dynamically inspects repository manifests and routes files based on extension:

| Ecosystem | Extensions | Parser Grammar | AST Model |
| :--- | :--- | :--- | :--- |
| **JavaScript** | `.js`, `.mjs`, `.cjs` | `tree-sitter-javascript` | `JSTSASTModel` |
| **JavaScript (React/JSX)** | `.jsx` | `tree-sitter-javascript` | `JSTSASTModel` |
| **TypeScript** | `.ts`, `.mts`, `.cts` | `tree-sitter-typescript` | `JSTSASTModel` |
| **TypeScript (React/TSX)** | `.tsx` | `tree-sitter-typescript` (TSX grammar) | `JSTSASTModel` |

---

## 2. Parser Architecture & Error Tolerance

Entropy utilizes Tree-sitter via direct Python C-bindings for lightning-fast parsing (~2–5ms per file) without runtime subprocesses.

```
Source File (.js / .ts / .jsx / .tsx)
                   │
                   ▼
     Tree-sitter Language Parser
  (javascript / typescript / tsx)
                   │
                   ▼
     Error Recovery & Validation
       (has_fatal_syntax_error)
        ├── If fatal: emit ENT-PARSE-001
        └── If valid / recoverable:
                   │
                   ▼
             JSTSVisitor
   (ast extraction & normalization)
                   │
                   ▼
             JSTSASTModel
   (functions, classes, catches, imports,
    calls, string literals, env lookups)
                   │
                   ▼
         JSTSAnalysisContext
                   │
                   ▼
      Phase 3–9 Debt Rule Analyzers
```

### Resilient AST Extraction
- **Error Tolerance**: Tree-sitter generates local `ERROR` nodes for harmless syntax anomalies (such as JSX entity encodings or unclosed trailing tags). The parser tolerates non-fatal errors while rejecting unparseable files with deterministic `ENT-PARSE-001` findings.
- **Python 3.14 C-API Compatibility**: AST extraction uses robust, garbage-collection-safe point and byte indexing to guarantee memory safety and zero memory corruption under modern Python runtimes.

---

## 3. Detection Rule Catalog

Entropy's Phase 11 rules integrate directly into the existing debt categories and scoring engine:

### A. Error Handling Debt

| Rule ID | Name | Severity | Description |
| :--- | :--- | :--- | :--- |
| **ENT-ERR-JS-001** | Empty / No-Op Catch Block | Medium | `catch (e) {}` blocks that discard exceptions without logging, rethrowing, or handling. |
| **ENT-ERR-JS-002** | Swallowed Error Fallback | Low | Catch blocks that swallow exceptions and return a fallback value (`null`, `false`, `""`) without error-level logging. |

### B. Input Validation Consistency

| Rule ID | Name | Severity | Description |
| :--- | :--- | :--- | :--- |
| **ENT-INPUT-JS-001** | Unvalidated HTTP Input in Sensitive Sink | High | Route handlers (Express, Next.js API, Fastify) passing `req.body`, `req.query`, or `req.params` directly to sensitive execution sinks (`eval`, `child_process.exec`, `innerHTML`, `document.write`). |

### C. Logging & Secret-Handling Debt

| Rule ID | Name | Severity | Description |
| :--- | :--- | :--- | :--- |
| **ENT-LOG-JS-001** | Sensitive Credential Logged | High | Logging calls (`console.log`, `console.info`, `logger.debug`) containing password, token, authorization header, or secret identifiers. |
| **ENT-LOG-JS-002** | Hardcoded Secret in Source Code | High | Static string literals with high Shannon entropy (>3.2) or matching known secret patterns (API tokens, private keys) assigned to credential variables. |
| **ENT-LOG-JS-003** | Inconsistent Secret Fallback | Medium | Environment variable secret lookups with insecure fallback literals (`process.env.JWT_SECRET \|\| "default_key"`). |

### D. Code Duplication & Boilerplate

| Rule ID | Name | Severity | Description |
| :--- | :--- | :--- | :--- |
| **ENT-DUP-001** | Duplicate Function Implementation | Medium | Semantically identical functions across JS/TS modules identified through normalized AST structure and token hashing. |
| **ENT-DUP-002** | Duplicate Code Block | Low | Repeated non-trivial structural code blocks exceeding size thresholds. |
| **ENT-DUP-004** | Boilerplate Wrapper Debt | Low | Highly repetitive boilerplate error handling or parameter extraction patterns. |

### E. Architectural Consistency

| Rule ID | Name | Severity | Description |
| :--- | :--- | :--- | :--- |
| **ENT-ARCH-001** | Circular Module Dependency | Medium | Circular import graphs detected between local JavaScript and TypeScript modules (`import`, `export ... from`, `require`). |

---

## 4. Pipeline & Persistence Integration

All JS/TS findings participate identically in:
1. **Finding Fingerprinting**: Stable SHA-256 fingerprints ensure identical findings retain consistent IDs across scans.
2. **Entropy Scoring**: Scores are calibrated identically across Python, JavaScript, and TypeScript components based on severity and category weights.
3. **Scan History & Diff Intelligence (Phase 10)**: Differential analysis seamlessly computes `new_findings`, `resolved_findings`, and `persisted_findings` across commits regardless of language.
4. **AI Explanation & Remediation (Phase 7)**: Findings trigger targeted, prompt-injection-safe remediation suggestions via the unified AI service.

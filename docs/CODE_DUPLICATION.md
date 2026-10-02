# Phase 8 — Code Duplication & Boilerplate Debt Analyzer

## Overview

The **Code Duplication & Boilerplate Debt Analyzer** is Entropy's Phase 8 static analysis component designed to detect structural duplication, redundant boilerplate, and copy-pasted implementations across Python codebases.

### The Core Product Principle

> **Entropy measures observable structural duplication that increases maintenance debt, regardless of who or what wrote the code. It makes no claims about AI authorship.**

Entropy does not attempt to detect AI-generated code, watermarks, or model stylometry. Both human developers and generative AI models can introduce boilerplate, copy-paste patterns, or un-refactored structural redundancies. Entropy flags code duplication purely as a software engineering and maintenance liability: when logic is duplicated across multiple functions or files, bug fixes must be applied in multiple places, increasing the likelihood of divergence, security oversights, and technical debt.

---

## Architecture

The Duplication Analyzer integrates seamlessly into Entropy's deterministic analysis pipeline:

```text
Repository Ingestion (Phase 1)
        ↓
Structural AST Parsing (Phase 2)
        ↓
AnalysisContext (ASTs, symbol tables, file manifests)
        ↓
CodeDuplicationDebtAnalyzer (Phase 8)
    ├── Path / File Exclusion Filtering
    ├── AST Normalization (Anonymization & Tokenization)
    ├── Exact Structural Hash Matching (O(N))
    ├── Size-Bucket & Operator Candidate Filtering
    ├── Structural Sequence Alignment (difflib SequenceMatcher >= 0.85)
    ├── Graph Clustering (BFS Connected Components)
    └── Deterministic Finding Generation (ENT-DUP-001 through ENT-DUP-005)
        ↓
Entropy Scoring Engine (Phase 4 - Weight 0.15 for code_duplication)
        ↓
Advisory AI Explanations & Remediation (Phase 7 - Optional)
```

---

## AST Normalization Algorithm

Comparing raw source text or tokens directly is brittle because it is sensitive to trivial variable renaming, comments, and whitespace differences. Conversely, naive token streams discard important structural semantics.

Entropy uses an AST-level normalizer (`ASTNormalizer`) that:
1. **Anonymizes Parameter & Local Variable Identifiers**:
   - Parameters are sequentially mapped to `$p1, $p2, ...`
   - Local variable names are mapped in order of first appearance to `$v1, $v2, ...`
   - Built-ins (`len`, `range`, `isinstance`, `print`, etc.), standard library symbols, and exception types (`ValueError`, `Exception`) are preserved.
2. **Strips Trivial Elements**:
   - Docstrings, inline comments, and type annotations are excluded from normalized structural tokens.
3. **Preserves Critical Semantics**:
   - AST node types (`FunctionDef`, `If`, `For`, `While`, `Try`, `ExceptHandler`, `Return`, etc.)
   - Operator types (`Add`, `Sub`, `Mult`, `Div`, `Eq`, `NotEq`, `Lt`, etc.)
   - Control flow structure and nesting depth.
   - Numeric literals that convey domain or status logic (e.g., HTTP status codes `200` vs `404`).
4. **Extracts Fingerprints**:
   - `exact_hash`: SHA-256 fingerprint over the normalized structural token string.
   - `operator_set`: Set of AST operator names used in the function for rapid candidate pruning.
   - `statement_count` and `node_count`: Used for size-bucketing and triviality filtering.

---

## Thresholds & Filtering

To maintain high signal-to-noise ratio and prevent false positives on common Python idioms:

| Parameter | Threshold | Purpose |
| :--- | :--- | :--- |
| **Minimum Statements** | `>= 2` | Excludes trivial single-line forwarding methods, `pass`, or single `return`. |
| **Minimum AST Nodes** | `>= 10` | Excludes trivial getters, setters, and basic property stubs. |
| **Similarity Threshold** | `>= 0.85` | Required ratio for `SequenceMatcher` to classify two non-identical functions as structural clones (`ENT-DUP-002`). |
| **Size Ratio Bounds** | `0.70 <= len(A)/len(B) <= 1.43` | Prunes candidate pairs with disparate lengths before sequence alignment. |
| **Cluster Minimum Size** | `>= 3` | A cluster finding (`ENT-DUP-005`) requires at least 3 duplicate functions across the codebase. |

---

## Graph Clustering Algorithm

Instead of reporting quadratic $O(N^2)$ pairwise clone findings which flood reports, Entropy groups related duplicates into coherent clusters:

1. **Exact Groups ($O(N)$)**:
   - Functions are grouped by their SHA-256 `exact_hash`. Any group with size $\ge 2$ forms an exact structural duplicate set.
2. **Approximate Candidate Reduction**:
   - Functions are partitioned into logarithmic size buckets based on AST node count.
   - Pairwise sequence matching is only evaluated between functions in identical or adjacent size buckets with compatible operator sets.
3. **Connected Components (BFS Graph Traversal)**:
   - Functions with similarity $\ge 0.85$ form edges in a duplication graph.
   - Breadth-first search traverses the graph to discover connected components.
4. **Primary vs. Duplicate Designation**:
   - The instance appearing first by file path (alphabetical) and line number is designated as the `canonical` instance.
   - All subsequent instances in the cluster are recorded with precise line ranges, file paths, and snippets as duplicate evidence.

---

## Detection Rules

| Rule ID | Rule Name | Severity | Description |
| :--- | :--- | :--- | :--- |
| **ENT-DUP-001** | Exact Structural Duplication | Medium | Two functions have identical normalized AST structure (excluding variable names/formatting). |
| **ENT-DUP-002** | Highly Similar Function | Low | Two functions share $\ge 85\%$ structural similarity with identical control flow. |
| **ENT-DUP-003** | Repeated Boilerplate Pattern | Low | Repetitive boilerplate blocks (e.g. repeated try/except error wrappers or validation boilerplate). |
| **ENT-DUP-004** | Cross-File Structural Duplication | Medium | Exact or near-identical duplication spanning across different files/modules. |
| **ENT-DUP-005** | Duplication Cluster | High | 3 or more functions across the repository share identical or near-identical implementations. |

---

## Time & Space Complexity

1. **AST Extraction & Normalization**:
   - Time: $O(M)$ where $M$ is the total number of AST nodes across all non-excluded files.
   - Space: $O(F)$ where $F$ is the number of analyzed functions.
2. **Exact Matching**:
   - Time: $O(F)$ using hash maps for hash collisions.
3. **Approximate Candidate Alignment**:
   - Size bucketing and operator set pruning reduce the search space from $O(F^2)$ to $O(\sum B_i^2)$ where $B_i \ll F$.
   - difflib `SequenceMatcher` is run strictly on tokenized structural representations.
4. **Clustering**:
   - Graph BFS runs in $O(V + E)$ where $V \le F$ and $E$ is the number of clone pairs.

The entire analysis completes in hundreds of milliseconds even on large codebases.

---

## Excluded Paths & Files

Entropy strictly ignores test suites, build outputs, and vendor directories to avoid false positives on legitimate test fixtures or generated code:

- `tests/`, `test/`
- `fixtures/`
- `migrations/`
- `alembic/`
- `vendor/`, `node_modules/`
- `.venv/`, `venv/`, `env/`
- `dist/`, `build/`, `.git/`

---

## Remediation Strategies

When duplication is flagged by Entropy:
1. **Extract Shared Utility Function**: Move duplicated algorithmic or transformation logic into a shared module.
2. **Parameterize Variations**: If two functions differ only in configuration, replace them with a single function accepting options or strategy arguments.
3. **Template Method or Decorator**: Replace repeated try/except or logging wrappers with a reusable Python decorator or context manager.

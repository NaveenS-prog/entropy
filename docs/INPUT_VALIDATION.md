# Entropy Input Validation Consistency Specification

## 1. Executive Summary & Purpose

Phase 6 extends Entropy's deterministic static analysis engine to evaluate **input validation debt and consistency** across Python web applications.

> **Disclaimer:**
> *Entropy identifies statically observable security-control inconsistencies and architectural debt. A finding is not by itself proof of exploitability, vulnerability, or a compromised system. The analyzer surfaces unvalidated external inputs, inconsistent validation paradigms across related routes, and unsafe direct sink consumption that create ongoing maintenance overhead and latent risk.*

---

## 2. Core Philosophy: Input Validation Consistency

Entropy analyzes how external data enters web handlers, whether validation mechanisms are applied, and how data flows toward sensitive operations:

| Category ID | Display Name | Target Area | Analyzer Class |
| :--- | :--- | :--- | :--- |
| `input_validation` | Input Validation | Route inputs, schemas, parameters, sinks | `InputValidationConsistencyAnalyzer` |

Rules, evidence, finding IDs, and scoring categories are strictly segregated. Entropy does not attempt whole-program taint analysis; rather, it performs deterministic intra-procedural AST inspection to detect unvalidated parameters, cross-route validation discrepancies, and unverified data feeding directly into critical sinks.

---

## 3. Supported Web Frameworks & Input Detection

All framework analysis is performed strictly on Python AST representations without importing target code or executing application logic:

- **FastAPI**: Identifies handler parameter signatures, inspecting parameter type annotations for Pydantic `BaseModel` schemas, dataclasses, primitive scalar annotations (`int`, `float`, `bool`, `UUID`), `Form(...)`, `File(...)`, and unannotated or generic container parameters (`dict`, `Any`, `request: Request`).
- **Flask**: Identifies direct attribute access on `request` (`request.args`, `request.form`, `request.json`, `request.values`, `request.data`, `request.files`).
- **Django**: Identifies direct access on `request.GET`, `request.POST`, `request.data`, `request.FILES`, and view method parameters.

### Validation Mechanisms Recognized
- **Schema Validation**: Pydantic models (`BaseModel`), Marshmallow schemas, dataclasses, DRF serializers.
- **Type Constraints**: Strict scalar primitive types (`int`, `float`, `bool`, `UUID`).
- **Constraint / Bounds Checking**: Explicit length checks (`len(...) > 0`), range/comparison checks (`<`, `<=`, `>`, `>=`), membership checks (`in allowed_list`), regex checks (`re.match(...)`), or explicit validation helper calls (`validate_*`, `is_valid`).

### False-Positive Suppression
Functions decorated with non-route markers are automatically excluded from endpoint analysis:
- CLI commands (`@click.command`, `@cli.command`, `@app.command`)
- Asynchronous task workers (`@celery.task`, `@shared_task`, `@task`)
- Test harnesses (`@pytest.fixture`, `@fixture`)
- Standard Python builtins (`@classmethod`, `@staticmethod`, `@property`)
- Internal utility functions not decorated as web endpoints

---

## 4. Rule Catalog

### `ENT-INPUT-001`: Potentially Unvalidated External Input
- **Severity**: `MEDIUM`
- **Default Confidence**: `HIGH` (for raw request body access or completely unannotated parameters) / `MEDIUM` (for generic dicts)
- **Description**: Identifies security-sensitive endpoints or route handlers that directly accept externally supplied inputs without recognizable schema validation, type constraints, or bounds checking.
- **Suppression**: If an endpoint is part of a route group exhibiting inconsistent validation across siblings, `ENT-INPUT-001` is suppressed on that endpoint in favor of `ENT-INPUT-002`.

### `ENT-INPUT-002`: Inconsistent Input Validation
- **Severity**: `MEDIUM`
- **Default Confidence**: `HIGH`
- **Description**: Detects related endpoints within the same route group (shared URL path prefix or router/blueprint) that handle comparable external inputs but utilize materially different validation approaches (e.g. one endpoint strictly enforces a Pydantic schema while a sibling endpoint accepts raw dictionaries or unvalidated `request.json`).

### `ENT-INPUT-003`: Unsafe Direct Input Usage
- **Severity**: `HIGH` (for dynamic query/subprocess execution) / `MEDIUM` (for filesystem paths or redirects)
- **Default Confidence**: `HIGH`
- **Description**: Detects unvalidated external input variables flowing directly into security-sensitive sinks without intermediate validation. Sinks inspected include:
  - Raw SQL query formatting (`execute(f"SELECT ...")`, `cursor.execute(...)`)
  - Subprocess execution (`subprocess.run(...)`, `os.system(...)`, `os.popen(...)`)
  - Filesystem path traversal risks (`open(...)`, `os.remove(...)`, `shutil.rmtree(...)`)
  - Dynamic code evaluation (`eval(...)`, `exec(...)`, `__import__(...)`)
  - Template injection (`render_template_string(...)`, `Template(...)`)
  - Unvalidated redirects (`redirect(...)`, `HttpResponseRedirect(...)`)

---

## 5. Evidence Models

Observable input validation patterns are captured in structured models:

### `InputValidationEvidence`
- `source_location`: Line, column, and file range in target file
- `endpoint`: Function symbol name
- `input_source`: Source of input (e.g. `FASTAPI_PARAM`, `FLASK_REQUEST_JSON`, `DJANGO_REQUEST_GET`)
- `validation_mechanism`: Applied mechanism (`SCHEMA_VALIDATION`, `TYPE_CONSTRAINT`, `EXPLICIT_BOUNDS_CHECK`, `NONE`)
- `sink`: Sensitive sink if applicable (`SQL_QUERY`, `SUBPROCESS_COMMAND`, `FILESYSTEM_PATH`, etc.)
- `confidence`: Confidence score based on AST precision
- `details`: Human-readable explanation of the observed input flow

### `EndpointInputProfile`
- `endpoint`: Route definition representation
- `evidences`: List of `InputValidationEvidence` items discovered for this endpoint
- `has_schema_validation`: Boolean indicator of schema-backed validation
- `has_unvalidated_input`: Boolean indicator of unvalidated external parameters

---

## 6. Scoring Integration

The `input_validation` category directly integrates into the Phase 4 Deterministic Entropy Scoring Engine:
- **Baseline Weight**: 0.20
- **Scale Factor**: 1000 LOC normalization
- **Severity Multipliers**:
  - `HIGH`: 3.0 (e.g., `ENT-INPUT-003` direct SQL/subprocess sinks)
  - `MEDIUM`: 1.5 (e.g., `ENT-INPUT-001`, `ENT-INPUT-002`)
  - `LOW`: 0.5
- **Confidence Weights**:
  - `HIGH`: 1.0
  - `MEDIUM`: 0.7
  - `LOW`: 0.3
- **Clamping**: Bounded strictly within `[0.0, 100.0]`. When no findings are present, category score is `0.0`.

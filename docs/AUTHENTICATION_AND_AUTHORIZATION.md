# Entropy Authentication & Authorization Consistency Specification

## 1. Executive Summary & Purpose

Phase 5 extends Entropy's deterministic static analysis engine beyond error-handling debt to evaluate **architectural security debt** across Python web applications.

> **Disclaimer:**
> *Entropy identifies statically observable security-control inconsistencies and architectural debt. A finding is not by itself proof of exploitability, vulnerability, or a compromised system. The analyzer surfaces unstandardized, duplicated, or missing security controls that create ongoing maintenance overhead and latent risk.*

---

## 2. Core Concepts: Authentication vs. Authorization

Entropy strictly separates two distinct security boundaries:

| Concept | Question Answered | Debt Category | Analyzer Class |
| :--- | :--- | :--- | :--- |
| **Authentication (AuthN)** | *"Who is this client/user?"* | `authentication_consistency` | `AuthenticationConsistencyAnalyzer` |
| **Authorization (AuthZ)** | *"Is this authenticated user permitted to execute this action?"* | `authorization_consistency` | `AuthorizationConsistencyAnalyzer` |

Rules, evidence, finding IDs, and scoring categories are strictly segregated. An endpoint may be properly authenticated yet completely lack authorization, or vice-versa.

---

## 3. Supported Web Frameworks & Static Route Discovery

All framework analysis is performed strictly on Python AST representations without importing target code or executing application logic:

- **FastAPI**: Identifies route decorators (`@app.get`, `@router.post`, `@api.put`, etc.), `APIRouter(prefix=...)` definitions, `Depends(...)` dependencies in route parameters, and middleware references.
- **Flask**: Identifies `@app.route(...)`, `@bp.route(...)`, HTTP method shorthand decorators (`@bp.get`, `@bp.post`), Blueprint configurations, and decorator-based guards.
- **Django**: Identifies URL patterns in `urlpatterns` (`path(...)`, `re_path(...)`), function-based views (FBVs) with `@login_required` / `@permission_required`, and class-based views (CBVs) inheriting from `View` or `APIView`.

### False-Positive Suppression
Functions decorated with non-route markers are automatically excluded from endpoint analysis:
- CLI commands (`@click.command`, `@cli.command`, `@app.command`)
- Asynchronous task workers (`@celery.task`, `@shared_task`, `@task`)
- Test harnesses (`@pytest.fixture`, `@fixture`)
- Standard Python builtins (`@classmethod`, `@staticmethod`, `@property`)

---

## 4. Rule Catalog

### Authentication Rules (`authentication_consistency`)

#### `ENT-AUTH-001`: Potentially Unprotected Security-Sensitive Endpoint
- **Severity**: `MEDIUM`
- **Default Confidence**: `MEDIUM` (escalated to `HIGH` for obvious administrative paths)
- **Description**: Identifies endpoints with security-sensitive route paths or handler names (e.g., matching keywords `admin`, `user`, `account`, `payment`, `billing`, `secret`, `role`, `permission`) where no static authentication evidence (decorator, dependency, or guard call) is observed.
- **Suppression**: If an endpoint is part of a route group with inconsistent authentication across siblings, `ENT-AUTH-001` is suppressed in favor of the more specific group inconsistency finding `ENT-AUTH-002`.

#### `ENT-AUTH-002`: Inconsistent Authentication Enforcement
- **Severity**: `MEDIUM`
- **Default Confidence**: `HIGH`
- **Description**: Compares structurally related endpoints within the same route group (shared path prefix or router/blueprint). If the majority (or ≥50%) of sibling routes enforce authentication (e.g. `GET /profile/view` and `GET /profile/settings` require `get_current_user`), but an unauthenticated route exists in the same group (e.g. `GET /profile/export`), an inconsistency finding is reported.

#### `ENT-AUTH-003`: Duplicated Local Authentication Logic
- **Severity**: `LOW`
- **Default Confidence**: `HIGH`
- **Description**: Detects identical or near-identical inline authentication checks (e.g. repeated `get_token_header`, manual JWT header extraction, or inline token verification) implemented independently across multiple endpoints rather than utilizing a shared framework dependency or middleware.

---

### Authorization Rules (`authorization_consistency`)

#### `ENT-AUTHZ-001`: Potentially Missing Authorization Check
- **Severity**: `HIGH` (for administrative keywords such as `admin`, `manage`, `grant`, `revoke`, `purge`, `destroy`) / `MEDIUM` (for sensitive resource mutations)
- **Default Confidence**: `HIGH` / `MEDIUM`
- **Description**: Flags sensitive endpoints—especially administrative routes or state-mutating actions on protected resources—that possess authentication but lack observable role, permission, or ownership checks.

#### `ENT-AUTHZ-002`: Inconsistent Authorization Enforcement
- **Severity**: `MEDIUM`
- **Default Confidence**: `HIGH`
- **Description**: Flags endpoints within an authorization-guarded route group where sibling routes enforce access control (e.g. `@require_role("admin")` or `Depends(require_admin)`), but an individual endpoint in the same group omits authorization guards.

#### `ENT-AUTHZ-003`: Duplicated Authorization Logic
- **Severity**: `LOW`
- **Default Confidence**: `HIGH`
- **Description**: Detects repeated inline authorization checks (such as verbatim `if user.role != "admin": raise HTTPException(403)` or repeated permission conditionals) across endpoints, recommending centralized dependency injection or policy decorators.

---

## 5. Evidence Models

Observable security patterns are normalized into typed representations:

### `AuthenticationEvidence`
- `mechanism_type`: `DECORATOR`, `DEPENDENCY`, `GUARD_CALL`, `MIDDLEWARE_REFERENCE`, `KNOWN_AUTH_HELPER`
- `source_location`: Line and column range in target file
- `endpoint`: Function symbol name
- `guard_name`: Identifier of the detected guard (e.g. `get_current_user`, `login_required`)
- `evidence_kind`: Syntactic pattern kind (e.g. `FASTAPI_DEPENDENCY`, `AUTH_DECORATOR`)
- `confidence`: `Confidence.HIGH`, `Confidence.MEDIUM`, `Confidence.LOW`
- `details`: Human-readable summary of the detected pattern

### `AuthorizationEvidence`
- `mechanism_type`: `ROLE_CHECK`, `PERMISSION_CHECK`, `OWNERSHIP_CHECK`, `POLICY_CHECK`, `AUTHORIZATION_DECORATOR`, `AUTHORIZATION_HELPER`
- `source_location`: Line and column range in target file
- `endpoint`: Function symbol name
- `role_or_permission`: Role or permission string if statically discoverable
- `evidence_kind`: Syntactic pattern kind (e.g. `AUTHZ_DECORATOR`, `INLINE_ROLE_CHECK`)
- `confidence`: `Confidence.HIGH`, `Confidence.MEDIUM`, `Confidence.LOW`
- `details`: Human-readable summary of the detected pattern

---

## 6. Integration with Phase 4 Scoring

With Phase 5 active:
1. `authentication_consistency` and `authorization_consistency` transitions from `NOT_ANALYZED` (`score: null`) to `ANALYZED` (`score: [0.0, 100.0]`).
2. If zero auth/authz findings are detected, their category scores are strictly `0.0`.
3. Categories not yet implemented (`input_validation`, `logging_and_secrets`, `code_duplication`, `architectural_consistency`) remain `NOT_ANALYZED` with `null` scores.
4. Total repository entropy score monotonically scales with the weighted density of findings across all active categories.

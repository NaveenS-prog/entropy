# Project Configuration (`.entropy.yml`)

Entropy project configuration allows repositories to declare deterministic project settings, analysis scopes, custom file exclusion patterns, baseline tracking, and rule suppression specifications.

---

## 1. File Location & Format

Entropy looks for `.entropy.yml` (or `.entropy.yaml`) at the repository root.

The configuration file must be valid YAML conforming to schema version 1.

```yaml
version: 1

project:
  name: "my-service"
  id: "srv-001"

analysis:
  languages:
    - python
    - javascript
    - typescript
  exclude:
    - "legacy/**"
    - "scripts/generated_*.py"

baseline:
  file: ".entropy-baseline.json"
  track_new_only: true

suppressions:
  rules:
    - rule_id: "ENT-ERR-001"
      reason: "Bare exceptions handled at global process boundary"
      paths:
        - "src/runner.py"
```

---

## 2. Configuration Schema

### `version` (required: integer)
Must be `1`. Other schema versions will cause validation to fail with exit code 2.

### `project` (object)
- `name` (string, required): Human-readable name of the project or repository.
- `id` (string, optional): Deterministic project identifier. If omitted, `name` is used as default.

### `analysis` (object)
- `languages` (list of strings, optional): Languages enabled for debt analysis. Defaults to `["python", "javascript", "typescript"]`.
- `exclude` (list of strings, optional): Glob patterns for files and directories to exclude from scanning, beyond the default exclusions (`.git`, `node_modules`, `__pycache__`, `.venv`, etc.).

### `baseline` (object)
- `file` (string, optional): Path to the baseline file relative to the repository root. Default: `.entropy-baseline.json`. Path traversal (`../` or absolute paths) is strictly prohibited.
- `track_new_only` (boolean, optional): If `true`, `entropy check` gates policy evaluation solely on new findings introduced relative to the baseline. Default: `false`.

### `suppressions` (object)
- `rules` (list of objects, optional): Global rule suppressions.
  - `rule_id` (string, required): A valid 38-rule Entropy rule ID (e.g., `ENT-ERR-001`, `ENT-AUTH-002`).
  - `reason` (string, required): Mandatory audit justification for why the rule is suppressed.
  - `paths` (list of strings, optional): Specific file paths or glob patterns where the suppression applies. If omitted, applies repository-wide.

---

## 3. Path Traversal & Security Protection

Entropy rejects unsafe configuration paths to prevent directory traversal vulnerabilities:
- Baseline paths containing `..` or pointing outside the repository root will fail schema validation.
- Exclusion patterns are evaluated strictly within the repository workspace.

---

## 4. Deterministic Configuration Hashing

Every scan computes a canonical SHA-256 hash of `.entropy.yml`:
- The configuration hash is calculated deterministically regardless of key ordering or whitespace differences.
- Stored on `RepositoryScanResult.config_hash` and `scan_snapshots.config_hash` to record exact configuration lineage.

---

## 5. Server Environment Configuration & Security Controls

Entropy exposes environment variables to constrain scanner filesystem access and enforce API authentication boundaries.

### `ENTROPY_SCAN_ALLOWED_ROOTS`
Restricts repository ingestion to authorized directory boundaries to prevent arbitrary local filesystem access. Entropy supports three parsing formats:
1. **Plain single path**:
   ```bash
   export ENTROPY_SCAN_ALLOWED_ROOTS=/var/entropy/repos
   ```
2. **Comma-separated paths**:
   ```bash
   export ENTROPY_SCAN_ALLOWED_ROOTS="/var/entropy/repos, /opt/projects, /home/user/workspaces"
   ```
3. **JSON array string**:
   ```bash
   export ENTROPY_SCAN_ALLOWED_ROOTS='["/var/entropy/repos", "/opt/projects"]'
   ```
If an invalid JSON array format is supplied (e.g. `[malformed`), Entropy halts startup with a clean, descriptive `ValidationError` rather than an unhandled stack trace.

### `ENTROPY_API_KEY`
API key required for all `/api/v1` routes (supplied in `X-API-Key` HTTP header). Keys are verified using constant-time comparison (`hmac.compare_digest`) to prevent timing side-channel attacks.

### `ENTROPY_ALLOW_LOCALHOST_NO_KEY`
When `ENTROPY_API_KEY` is omitted:
- Defaults to `true` for developer CLI workflows and `./scripts/dev.sh`.
- Defaults to `false` when running via `uvicorn` in production or standard deployment settings.
- When `false` and no API key is set, all requests to protected endpoints fail with `401 Unauthorized`.

> [!CAUTION]
> **Reverse Proxy Security Hazard**: When Entropy runs behind a reverse proxy (e.g., Nginx, Envoy, AWS ALB, Traefik), the TCP peer socket address observed by FastAPI is the IP address of the reverse proxy (often `127.0.0.1`). If `ENTROPY_ALLOW_LOCALHOST_NO_KEY=true` is enabled behind a reverse proxy, external untrusted traffic forwarding through the proxy will appear as localhost and bypass authentication.
> 
> For security, Entropy **never** trusts or inspects `X-Forwarded-For` or `X-Real-IP` headers to determine localhost exemption. When deploying behind a reverse proxy, you MUST configure `ENTROPY_API_KEY` and ensure `ENTROPY_ALLOW_LOCALHOST_NO_KEY=false`.

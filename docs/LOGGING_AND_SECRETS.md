# Entropy Logging & Secret-Handling Debt Specification

## 1. Executive Summary & Purpose

Phase 6 extends Entropy's deterministic static analysis engine to evaluate **logging debt, sensitive data exposure, and hardcoded credentials** across Python codebases.

> **Disclaimer:**
> *Entropy identifies statically observable security-control inconsistencies and architectural debt. A finding is not by itself proof of exploitability, vulnerability, or a compromised system. The analyzer surfaces hardcoded credential patterns, sensitive field logging, and insecure fallback configurations that create ongoing maintenance overhead and latent risk.*

---

## 2. Core Philosophy: Logging & Secret Handling

Entropy analyzes static syntax trees for two interrelated anti-patterns:
1. **Exposure of Sensitive Data in Logs**: Passwords, tokens, keys, authorization headers, or whole user/request objects printed to application logs.
2. **Hardcoded Secrets & Fragile Fallbacks**: Cryptographic secrets, API tokens, and credentials embedded directly in code or configured with insecure fallback defaults.

| Category ID | Display Name | Target Area | Analyzer Class |
| :--- | :--- | :--- | :--- |
| `logging_and_secrets` | Logging & Secrets | Log invocations, string literals, env lookups | `LoggingAndSecretsAnalyzer` |

Entropy uses deterministic AST traversal and Shannon entropy calculations on candidate string literals, completely avoiding nondeterministic heuristic guessing or runtime evaluation.

---

## 3. Supported Logging Frameworks & Static Discovery

Entropy inspects call sites for common Python logging APIs:
- Standard library `logging`: `logger.debug()`, `logger.info()`, `logger.warning()`, `logger.error()`, `logger.critical()`, `logger.exception()`, `logging.info()`, etc.
- Structured loggers: `loguru.logger.*`, `structlog.get_logger().*`, `print()` in server handlers.

### Sensitive Identifier Recognition
Entropy matches identifiers against canonical sensitive keywords:
- `password`, `passwd`, `pwd`, `secret`, `token`, `api_key`, `access_token`, `refresh_token`, `auth_header`, `bearer`, `private_key`, `credentials`, `ssn`, `credit_card`.

### High-Entropy Secret Detection
Entropy detects hardcoded credentials using a hybrid technique:
1. **Known High-Confidence Prefixes**: `sk_live_`, `sk_test_`, `ghp_`, `gho_`, `glpat-`, `xoxb-`, `xoxp-`, `AKIA`, `AIzaSy`.
2. **Shannon Entropy Analysis**: Strings exceeding length thresholds (≥ 20 characters) and minimum Shannon entropy ($H \ge 3.5$) assigned to sensitive variable names or config constants.

### False-Positive Suppression
- Placeholder values (`placeholder`, `dummy`, `example`, `your_api_key_here`, `xxx`, `changeme`, `TODO`, `FIXME`, empty strings) are excluded.
- Format string template variables (`{token}`, `%s`, `Bearer %s`) without attached runtime values are not flagged as hardcoded secrets.
- Test files located in `tests/`, `testing/`, or prefixed with `test_` are evaluated with appropriate context.

---

## 4. Rule Catalog

### `ENT-LOG-001`: Potentially Sensitive Data in Log Messages
- **Severity**: `HIGH` (for plaintext passwords/tokens) / `MEDIUM` (for session/header identifiers)
- **Default Confidence**: `HIGH`
- **Description**: Identifies log statements that format or concatenate sensitive variable names (such as passwords, tokens, API keys, or credit cards) into log messages or pass them via structured `extra` fields.

### `ENT-LOG-002`: Hardcoded Secret or Credential
- **Severity**: `HIGH` (for live provider prefixes) / `MEDIUM` (for generic high-entropy strings)
- **Default Confidence**: `HIGH`
- **Description**: Detects hardcoded cryptographic keys, database passwords, API tokens, and access credentials assigned to variables or passed to configuration constructors.

### `ENT-LOG-003`: Logging of Sensitive Objects
- **Severity**: `MEDIUM`
- **Default Confidence**: `MEDIUM`
- **Description**: Flags logging statements that serialize entire composite objects likely to contain sensitive fields, such as full `request` objects, `user` models, `session` state, or unredacted database model instances.

### `ENT-LOG-004`: Inconsistent Secret Fallback
- **Severity**: `MEDIUM`
- **Default Confidence**: `HIGH`
- **Description**: Detects environment variable lookups for sensitive credentials (`os.getenv(...)`, `os.environ.get(...)`) that supply hardcoded fallback values in non-test production code (e.g. `os.getenv('SECRET_KEY', 'default_secret')`).

---

## 5. Evidence Models

Observable logging and secret patterns are captured in structured models:

### `LoggingEvidence`
- `source_location`: Line and column range in target file
- `logger_name`: Logger identifier (e.g. `logger`, `log`, `logging`)
- `method_name`: Log level (`info`, `error`, `debug`, etc.)
- `sensitive_identifiers`: List of sensitive tokens found in the call arguments or extra payload
- `evidence_kind`: Syntactic pattern (e.g. `LOG_CALL_ARGUMENT`, `LOG_FORMAT_VARIABLE`, `STRUCTURED_LOG_EXTRA`)
- `details`: Human-readable explanation of the detected exposure

### `SecretEvidence`
- `source_location`: Line and column range in target file
- `variable_name`: Target variable or setting receiving the value
- `secret_kind`: Categorization (`LIVE_API_KEY`, `HIGH_ENTROPY_TOKEN`, `INSECURE_ENV_FALLBACK`)
- `entropy_score`: Calculated Shannon entropy for candidate strings
- `details`: Diagnostic summary (with secret content safely truncated/redacted)

---

## 6. Scoring Integration

The `logging_and_secrets` category directly integrates into the Phase 4 Deterministic Entropy Scoring Engine:
- **Baseline Weight**: 0.20
- **Scale Factor**: 1000 LOC normalization
- **Severity Multipliers**:
  - `HIGH`: 3.0 (e.g., `ENT-LOG-001` password logging, `ENT-LOG-002` live API keys)
  - `MEDIUM`: 1.5 (e.g., `ENT-LOG-003` sensitive object logging, `ENT-LOG-004` insecure fallback)
  - `LOW`: 0.5
- **Confidence Weights**:
  - `HIGH`: 1.0
  - `MEDIUM`: 0.7
  - `LOW`: 0.3
- **Clamping**: Bounded strictly within `[0.0, 100.0]`. When no findings are present, category score is `0.0`.

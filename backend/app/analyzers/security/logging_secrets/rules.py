"""Rule definitions and implementations for Logging and Secret Handling Debt Analyzer."""

from __future__ import annotations

import ast
import math

from app.analyzers.context import PythonASTContext
from app.analyzers.rules.base import BaseRule
from app.models.domain.enums import Confidence, DebtCategory, Severity
from app.models.domain.finding import Finding

# Common logging methods
LOGGING_METHODS = {
    "info",
    "debug",
    "warning",
    "warn",
    "error",
    "exception",
    "critical",
    "fatal",
}

# Sensitive identifier keywords
SENSITIVE_IDENTIFIERS = {
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "auth_token",
    "authorization",
    "bearer_token",
    "credit_card",
    "card_number",
    "ssn",
    "private_key",
    "session_token",
    "client_secret",
}

# Known live secret prefixes indicating high-confidence real credentials
KNOWN_SECRET_PREFIXES = (
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "ghp_",
    "gho_",
    "xoxb-",
    "xoxp-",
    "AKIA",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
)

# Harmless placeholder values to ignore
EXACT_PLACEHOLDERS = {
    "password",
    "secret",
    "default",
    "123456",
    "admin",
    "none",
    "null",
    "localhost",
    "test",
}

PLACEHOLDER_SUBSTRINGS = {
    "dummy",
    "placeholder",
    "example",
    "sample",
    "changeme",
    "change_me",
    "your_api_key",
    "your_secret",
    "your_key",
    "xxx",
    "mock",
    "fake",
    "todo",
    "fixme",
}


def _shannon_entropy(s: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not s:
        return 0.0
    entropy = 0.0
    length = len(s)
    for count in [s.count(c) for c in set(s)]:
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _is_logging_call(node: ast.Call) -> tuple[bool, str, str]:
    """Determine if an AST Call node represents a logging invocation.

    Returns (is_log, logger_name, method_name).
    """
    if not isinstance(node.func, ast.Attribute):
        return False, "", ""

    method_name = node.func.attr
    if method_name not in LOGGING_METHODS:
        return False, "", ""

    caller = ast.unparse(node.func.value) if hasattr(ast, "unparse") else ""
    norm_caller = caller.lower()

    if any(
        target in norm_caller
        for target in ("logger", "logging", "log", "app.logger", "self.logger")
    ):
        return True, caller, method_name

    return False, "", ""


def _is_sensitive_identifier(name: str) -> bool:
    """Check whether a variable or attribute name indicates sensitive data."""
    norm = name.lower()
    return any(sens in norm for sens in SENSITIVE_IDENTIFIERS)


# =============================================================================
# Rule Implementations
# =============================================================================


class SensitiveDataInLogsRule(BaseRule):
    """ENT-LOG-001: Sensitive Data in Logs."""

    @property
    def rule_id(self) -> str:
        return "ENT-LOG-001"

    @property
    def name(self) -> str:
        return "Sensitive Data in Logs"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.LOGGING_AND_SECRETS

    @property
    def description(self) -> str:
        return (
            "Detects sensitive values (passwords, tokens, API keys, credentials, or authorization headers) "
            "being passed as arguments or formatted into application logging calls."
        )

    @property
    def default_severity(self) -> Severity:
        return Severity.HIGH

    @property
    def default_confidence(self) -> Confidence:
        return Confidence.HIGH

    @property
    def impact(self) -> str:
        return (
            "Writing sensitive credentials into application logs exposes them to log aggregation platforms, "
            "monitoring tools, developers, and third-party observability providers, violating privacy regulations."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Sanitize, redact, or mask sensitive fields prior to logging. Never pass plain credentials, "
            "tokens, or passwords into log statements."
        )

    def analyze_file(self, context: PythonASTContext) -> list[Finding]:
        if not context.ast_root:
            return []

        findings: list[Finding] = []

        for node in ast.walk(context.ast_root):
            if not isinstance(node, ast.Call):
                continue

            is_log, logger_name, method_name = _is_logging_call(node)
            if not is_log:
                continue

            # Flag: check if call passes sensitive variables/attributes
            detected_sensitive: list[str] = []

            # 1. Positional Arguments beyond format string
            if len(node.args) > 1:
                for arg in node.args[1:]:
                    arg_str = ast.unparse(arg) if hasattr(ast, "unparse") else ""
                    if isinstance(arg, ast.Name) and _is_sensitive_identifier(arg.id):
                        detected_sensitive.append(arg.id)
                    elif isinstance(arg, ast.Attribute) and _is_sensitive_identifier(arg.attr):
                        detected_sensitive.append(arg.attr)
                    elif isinstance(arg, ast.Subscript):
                        sub_str = ast.unparse(arg).lower() if hasattr(ast, "unparse") else ""
                        if any(s in sub_str for s in SENSITIVE_IDENTIFIERS):
                            detected_sensitive.append(arg_str)

            # 2. Formatted Values in F-strings (args[0] or any arg)
            for arg in node.args:
                if isinstance(arg, ast.JoinedStr):
                    for part in arg.values:
                        if isinstance(part, ast.FormattedValue):
                            val_str = ast.unparse(part.value) if hasattr(ast, "unparse") else ""
                            if _is_sensitive_identifier(val_str):
                                detected_sensitive.append(val_str)

            # 3. Keyword Arguments (e.g. extra={"token": ...})
            for kw in node.keywords:
                if kw.arg == "extra" and isinstance(kw.value, ast.Dict):
                    for k, v in zip(kw.value.keys, kw.value.values, strict=False):
                        k_str = ast.unparse(k) if hasattr(ast, "unparse") and k else ""
                        v_str = ast.unparse(v) if hasattr(ast, "unparse") else ""
                        if _is_sensitive_identifier(k_str) or _is_sensitive_identifier(v_str):
                            detected_sensitive.append(f"extra:{k_str}")

            if detected_sensitive:
                sens_summary = ", ".join(sorted(set(detected_sensitive)))
                snippet = context.extract_snippet(
                    node.lineno,
                    getattr(node, "end_lineno", node.lineno),
                    context_before=1,
                    context_after=1,
                )

                # Severity: HIGH for credentials/tokens/passwords, MEDIUM for session/card
                is_credential = any(
                    k in sens_summary.lower()
                    for k in ("password", "token", "secret", "api_key", "apikey", "private_key")
                )
                severity = Severity.HIGH if is_credential else Severity.MEDIUM

                sig = f"{node.lineno}:{sens_summary}"
                fid = Finding.generate_deterministic_id(
                    rule_id=self.rule_id,
                    file=context.file_path,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    symbol=f"{logger_name}.{method_name}",
                    evidence_signature=sig,
                )
                fp = Finding.generate_fingerprint(
                    rule_id=self.rule_id,
                    file=context.file_path,
                    symbol=f"{logger_name}.{method_name}",
                    pattern_signature=sig,
                )
                finding = Finding(
                    id=fid,
                    fingerprint=fp,
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=severity,
                    confidence=self.default_confidence,
                    file=context.file_path,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    symbol=f"{logger_name}.{method_name}",
                    title=f"Sensitive Data ({sens_summary}) Logged via {logger_name}.{method_name}",
                    description=(
                        f"Logging statement in '{logger_name}.{method_name}' outputs sensitive value(s): "
                        f"{sens_summary}. Sensitive credentials must not be emitted to log streams."
                    ),
                    evidence=snippet,
                    impact=self.impact,
                    recommendation=self.recommendation,
                )
                findings.append(finding)

        return findings


class HardcodedSecretPatternRule(BaseRule):
    """ENT-LOG-002: Hardcoded Secret / Credential Pattern."""

    @property
    def rule_id(self) -> str:
        return "ENT-LOG-002"

    @property
    def name(self) -> str:
        return "Hardcoded Secret / Credential Pattern"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.LOGGING_AND_SECRETS

    @property
    def description(self) -> str:
        return (
            "Detects hardcoded API keys, private keys, passwords, or authentication tokens assigned "
            "as static string literals in source code."
        )

    @property
    def default_severity(self) -> Severity:
        return Severity.HIGH

    @property
    def default_confidence(self) -> Confidence:
        return Confidence.HIGH

    @property
    def impact(self) -> str:
        return (
            "Hardcoded secrets checked into source control are exposed to anyone with repository access, "
            "risk leakage via git history, and prevent seamless credential rotation."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Extract credentials into environment variables or a dedicated secrets manager (e.g. AWS Secrets "
            "Manager, GCP Secret Manager, Vault) and load them dynamically at runtime."
        )

    def analyze_file(self, context: PythonASTContext) -> list[Finding]:
        if not context.ast_root:
            return []

        findings: list[Finding] = []

        for node in ast.walk(context.ast_root):
            # Inspect assignments: Target = "..."
            var_name = ""
            val_node: ast.AST | None = None

            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name):
                    var_name = target.id
                    val_node = node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                var_name = node.target.id
                val_node = node.value

            if not var_name or not val_node or not isinstance(val_node, ast.Constant):
                continue

            val = val_node.value
            if not isinstance(val, str) or not val.strip():
                continue

            val_str = val.strip()

            # Ignore empty or very short strings
            if len(val_str) < 8:
                continue

            # False-positive mitigation: placeholder filtering
            low_val = val_str.lower()
            if low_val in EXACT_PLACEHOLDERS or any(ph in low_val for ph in PLACEHOLDER_SUBSTRINGS):
                continue

            # Check if variable name indicates credential/secret
            is_sensitive_var = _is_sensitive_identifier(var_name)
            has_known_prefix = any(val_str.startswith(p) for p in KNOWN_SECRET_PREFIXES)

            # Require either a known live secret prefix, OR a sensitive variable name with high entropy / non-trivial value
            is_secret = False
            confidence = Confidence.MEDIUM
            severity = Severity.HIGH

            if has_known_prefix:
                is_secret = True
                confidence = Confidence.HIGH
            elif is_sensitive_var and len(val_str) >= 12:
                entropy = _shannon_entropy(val_str)
                # Normal English words have entropy < 3.2; random keys / tokens typically > 3.4
                has_mixed_chars = (
                    any(c.isupper() for c in val_str)
                    and any(c.islower() for c in val_str)
                    and any(c.isdigit() for c in val_str)
                )
                if entropy > 3.3 or has_mixed_chars or len(val_str) >= 20:
                    is_secret = True
                    confidence = Confidence.HIGH if entropy > 3.8 or has_mixed_chars else Confidence.MEDIUM

            if is_secret:
                snippet = context.extract_snippet(
                    node.lineno,
                    getattr(node, "end_lineno", node.lineno),
                    context_before=1,
                    context_after=1,
                )
                masked_val = val_str[:4] + "..." + val_str[-4:] if len(val_str) > 10 else "***"

                sig = f"{var_name}:{node.lineno}"
                fid = Finding.generate_deterministic_id(
                    rule_id=self.rule_id,
                    file=context.file_path,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    symbol=var_name,
                    evidence_signature=sig,
                )
                fp = Finding.generate_fingerprint(
                    rule_id=self.rule_id,
                    file=context.file_path,
                    symbol=var_name,
                    pattern_signature=sig,
                )
                finding = Finding(
                    id=fid,
                    fingerprint=fp,
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=severity,
                    confidence=confidence,
                    file=context.file_path,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    symbol=var_name,
                    title=f"Hardcoded Secret Assigned to '{var_name}'",
                    description=(
                        f"Variable '{var_name}' is assigned a static string literal resembling a secret "
                        f"or credential ({masked_val}). Credentials should never be hardcoded."
                    ),
                    evidence=snippet,
                    impact=self.impact,
                    recommendation=self.recommendation,
                )
                findings.append(finding)

        return findings


class SensitiveObjectLoggingRule(BaseRule):
    """ENT-LOG-003: Sensitive Object Logging."""

    @property
    def rule_id(self) -> str:
        return "ENT-LOG-003"

    @property
    def name(self) -> str:
        return "Sensitive Object Logging"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.LOGGING_AND_SECRETS

    @property
    def description(self) -> str:
        return (
            "Detects logging of high-cardinality or sensitive objects (such as entire request objects, "
            "request headers, or user model instances) that commonly embed credentials or PII."
        )

    @property
    def default_severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def default_confidence(self) -> Confidence:
        return Confidence.HIGH

    @property
    def impact(self) -> str:
        return (
            "Logging entire request or user objects exposes raw headers (Authorization, Cookie), session "
            "tokens, and sensitive user attributes directly to log storage."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Log only necessary scalar identifiers (e.g. user_id, request_id, path) rather than dumping "
            "entire request, header, or user objects."
        )

    def analyze_file(self, context: PythonASTContext) -> list[Finding]:
        if not context.ast_root:
            return []

        findings: list[Finding] = []

        for node in ast.walk(context.ast_root):
            if not isinstance(node, ast.Call):
                continue

            is_log, logger_name, method_name = _is_logging_call(node)
            if not is_log or not node.args:
                continue

            logged_obj = ""

            # Check direct argument: logger.info(request) or logger.info(request.headers)
            for arg in node.args:
                arg_expr = ast.unparse(arg).lower().strip() if hasattr(ast, "unparse") else ""
                if arg_expr in ("request", "req") or arg_expr.endswith(".headers") or arg_expr in ("request.headers", "req.headers"):
                    logged_obj = arg_expr
                    break
                # Check format arg: logger.info("req=%s", request)
                if isinstance(arg, ast.Name) and arg.id.lower() in ("request", "req", "user", "session"):
                    logged_obj = arg.id
                    break
                if isinstance(arg, ast.Attribute) and arg.attr.lower() in ("headers", "raw_headers"):
                    logged_obj = ast.unparse(arg) if hasattr(ast, "unparse") else arg.attr
                    break
                if isinstance(arg, ast.JoinedStr):
                    for part in arg.values:
                        if isinstance(part, ast.FormattedValue):
                            pval = ast.unparse(part.value).lower().strip() if hasattr(ast, "unparse") else ""
                            if pval in ("request", "req", "request.headers", "req.headers", "headers"):
                                logged_obj = pval
                                break

            if logged_obj:
                snippet = context.extract_snippet(
                    node.lineno,
                    getattr(node, "end_lineno", node.lineno),
                    context_before=1,
                    context_after=1,
                )
                sig = f"{node.lineno}:{logged_obj}"
                fid = Finding.generate_deterministic_id(
                    rule_id=self.rule_id,
                    file=context.file_path,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    symbol=f"{logger_name}.{method_name}",
                    evidence_signature=sig,
                )
                fp = Finding.generate_fingerprint(
                    rule_id=self.rule_id,
                    file=context.file_path,
                    symbol=f"{logger_name}.{method_name}",
                    pattern_signature=sig,
                )
                finding = Finding(
                    id=fid,
                    fingerprint=fp,
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=self.default_severity,
                    confidence=self.default_confidence,
                    file=context.file_path,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    symbol=f"{logger_name}.{method_name}",
                    title=f"Sensitive Object '{logged_obj}' Emitted to Logs",
                    description=(
                        f"Logging call '{logger_name}.{method_name}' logs the sensitive object '{logged_obj}', "
                        f"which risks leaking authorization tokens, cookies, or user credentials."
                    ),
                    evidence=snippet,
                    impact=self.impact,
                    recommendation=self.recommendation,
                )
                findings.append(finding)

        return findings


class InconsistentSecretHandlingRule(BaseRule):
    """ENT-LOG-004: Inconsistent Secret Handling."""

    @property
    def rule_id(self) -> str:
        return "ENT-LOG-004"

    @property
    def name(self) -> str:
        return "Inconsistent Secret Handling"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.LOGGING_AND_SECRETS

    @property
    def description(self) -> str:
        return (
            "Detects inconsistent secret management, such as fallback hardcoded credential defaults in "
            "environment lookups or disparate retrieval mechanisms for credentials across modules."
        )

    @property
    def default_severity(self) -> Severity:
        return Severity.MEDIUM

    @property
    def default_confidence(self) -> Confidence:
        return Confidence.HIGH

    @property
    def impact(self) -> str:
        return (
            "Supplying hardcoded credential fallbacks allows applications to silently run with insecure "
            "defaults when environment variables are omitted, leading to credential compromises in deployment."
        )

    @property
    def recommendation(self) -> str:
        return (
            "Fail fast if critical environment secrets are missing instead of falling back to insecure "
            "hardcoded defaults (e.g. raise ValueError if not os.getenv('SECRET_KEY'))."
        )

    def analyze_file(self, context: PythonASTContext) -> list[Finding]:
        if not context.ast_root:
            return []

        findings: list[Finding] = []

        # Check for os.getenv("SECRET_KEY", "insecure_fallback_literal")
        for node in ast.walk(context.ast_root):
            if not isinstance(node, ast.Call):
                continue

            call_str = ast.unparse(node.func).lower() if hasattr(ast, "unparse") else ""
            if not any(target in call_str for target in ("os.getenv", "os.environ.get", "environ.get", "config.get")):
                continue

            # Check if call provides a default argument (args[1])
            if len(node.args) >= 2:
                key_arg = node.args[0]
                default_arg = node.args[1]

                key_str = ast.unparse(key_arg).lower() if hasattr(ast, "unparse") else ""
                if not any(sens in key_str for sens in SENSITIVE_IDENTIFIERS):
                    continue

                if isinstance(default_arg, ast.Constant) and isinstance(default_arg.value, str):
                    fallback_val = default_arg.value.strip()
                    # Skip empty string or recognized test dummy values
                    if not fallback_val or fallback_val.lower() in ("none", "null", ""):
                        continue
                    if len(fallback_val) >= 6 and not any(ph in fallback_val.lower() for ph in ("placeholder", "changeme", "dummy")):
                        snippet = context.extract_snippet(
                            node.lineno,
                            getattr(node, "end_lineno", node.lineno),
                            context_before=1,
                            context_after=1,
                        )
                        key_name = ast.unparse(key_arg) if hasattr(ast, "unparse") else "SECRET"
                        sig = f"{node.lineno}:{key_name}:fallback"
                        fid = Finding.generate_deterministic_id(
                            rule_id=self.rule_id,
                            file=context.file_path,
                            line_start=node.lineno,
                            line_end=getattr(node, "end_lineno", node.lineno),
                            symbol=call_str,
                            evidence_signature=sig,
                        )
                        fp = Finding.generate_fingerprint(
                            rule_id=self.rule_id,
                            file=context.file_path,
                            symbol=call_str,
                            pattern_signature=sig,
                        )
                        finding = Finding(
                            id=fid,
                            fingerprint=fp,
                            rule_id=self.rule_id,
                            category=self.category,
                            severity=self.default_severity,
                            confidence=self.default_confidence,
                            file=context.file_path,
                            line_start=node.lineno,
                            line_end=getattr(node, "end_lineno", node.lineno),
                            symbol=call_str,
                            title=f"Insecure Secret Fallback in {call_str}({key_name})",
                            description=(
                                f"Environment lookup for secret '{key_name}' supplies a hardcoded non-empty fallback literal. "
                                f"If the environment variable is unset, the system silently uses an insecure default secret."
                            ),
                            evidence=snippet,
                            impact=self.impact,
                            recommendation=self.recommendation,
                        )
                        findings.append(finding)

        return findings

"""JavaScript and TypeScript Logging and Secret-Handling static analysis rules."""

from __future__ import annotations

import math
import re

from app.analyzers.jsts_context import JSTSASTContext
from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.models.domain.finding import CodeEvidence, Finding
from app.models.domain.rule import RuleDefinition

LOGGING_CALLS = {
    "console.log",
    "console.info",
    "console.warn",
    "console.error",
    "console.debug",
    "logger.info",
    "logger.warn",
    "logger.error",
    "logger.debug",
    "log.info",
    "log.warn",
    "log.error",
    "log.debug",
}

SENSITIVE_LOG_IDENTIFIERS = [
    r"authorization",
    r"password",
    r"passwd",
    r"token",
    r"secret",
    r"apikey",
    r"api_key",
    r"private_key",
    r"credential",
]

SENSITIVE_VAR_TERMS = {
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "auth_token",
    "client_secret",
}

PLACEHOLDER_SUBSTRINGS = {
    "dummy",
    "placeholder",
    "example",
    "sample",
    "changeme",
    "change_me",
    "your_key",
    "your_secret",
    "your_token",
    "xxx",
    "mock",
    "fake",
    "test",
    "localhost",
}

CONFIG_ENV_VARS = {"port", "node_env", "host", "timeout", "app_env", "env", "version"}


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy for a string."""
    if not s:
        return 0.0
    entropy = 0.0
    length = len(s)
    for count in [s.count(c) for c in set(s)]:
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class JSSensitiveLogRule:
    """ENT-LOG-JS-001: Sensitive Data in Log Message."""

    rule_id = "ENT-LOG-JS-001"
    name = "Potentially Sensitive Data in Log Output"
    category = DebtCategory.LOGGING_AND_SECRETS
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    @property
    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            rule_id=self.rule_id,
            category=self.category,
            title=self.name,
            description="Logging statement outputs sensitive credential or header information.",
            default_severity=self.severity,
            default_confidence=self.confidence,
            languages=[SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
            impact_template="Exposes credentials and session tokens to log collectors, monitoring pipelines, and disk storage.",
            recommendation_template="Redact or omit sensitive properties (authorization headers, passwords, secrets) before logging.",
            rationale="Logging credentials creates silent audit and leakage debt in telemetry systems.",
        )

    def analyze(self, context: JSTSASTContext) -> list[Finding]:
        findings: list[Finding] = []
        for call in context.get_calls():
            callee_low = call.callee.lower()
            if not any(log_call in callee_low for log_call in LOGGING_CALLS):
                continue

            # Check arguments for sensitive items
            matched_sensitive: list[str] = []
            for arg in call.arguments:
                arg_low = arg.lower()
                for sens_pattern in SENSITIVE_LOG_IDENTIFIERS:
                    if re.search(sens_pattern, arg_low):
                        matched_sensitive.append(arg.strip())
                        break

            if not matched_sensitive:
                continue

            sens_summary = ", ".join(matched_sensitive)
            raw_snippet = context.extract_snippet(
                call.location.line_start,
                call.location.line_end,
                context_before=1,
                context_after=1,
            )

            # Redact sensitive values from evidence
            redacted_content = raw_snippet.content
            for sens in matched_sensitive:
                if "=" in sens or ":" in sens:
                    # Redact assignment value
                    redacted_content = re.sub(
                        r"(['\"][^'\"]*['\"])",
                        "'[REDACTED_SECRET]'",
                        redacted_content,
                    )

            redacted_evidence = CodeEvidence(
                content=redacted_content,
                line_start=raw_snippet.line_start,
                line_end=raw_snippet.line_end,
                highlight_lines=raw_snippet.highlight_lines,
            )

            sig = f"{call.callee}:{call.location.line_start}"
            fid = Finding.generate_deterministic_id(
                rule_id=self.rule_id,
                file=context.file_path,
                line_start=call.location.line_start,
                line_end=call.location.line_end,
                symbol=call.callee,
                evidence_signature=sig,
            )
            fp = Finding.generate_fingerprint(
                rule_id=self.rule_id,
                file=context.file_path,
                symbol=call.callee,
                pattern_signature=sig,
            )

            findings.append(
                Finding(
                    id=fid,
                    fingerprint=fp,
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=self.severity,
                    confidence=self.confidence,
                    file=context.file_path,
                    line_start=call.location.line_start,
                    line_end=call.location.line_end,
                    column_start=call.location.col_start,
                    column_end=call.location.col_end,
                    symbol=call.callee,
                    title="Potentially Sensitive Data in Log Output",
                    description=(
                        f"Logging statement '{call.callee}' in '{context.file_path}' outputs sensitive identifier(s): "
                        f"{sens_summary}. Sensitive authentication credentials must not be emitted to log streams."
                    ),
                    evidence=redacted_evidence,
                    impact="Credentials and tokens logged to files or monitoring consoles risk unauthorized exposure.",
                    recommendation="Remove sensitive parameters or sanitize them through an explicit masking utility.",
                )
            )

        return findings


class JSHardcodedSecretRule:
    """ENT-LOG-JS-002: Hardcoded Secret or Credential."""

    rule_id = "ENT-LOG-JS-002"
    name = "Hardcoded Secret / Credential Pattern"
    category = DebtCategory.LOGGING_AND_SECRETS
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    @property
    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            rule_id=self.rule_id,
            category=self.category,
            title=self.name,
            description="Static string literal in source code represents a hardcoded secret, token, or private key.",
            default_severity=self.severity,
            default_confidence=self.confidence,
            languages=[SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
            impact_template="Exposes credentials to anyone with repository access and prevents clean credential rotation.",
            recommendation_template="Store secrets in environment variables or a secrets manager (Vault, GCP Secret Manager).",
            rationale="Hardcoded credentials in source control accumulate persistent exposure risks.",
        )

    def analyze(self, context: JSTSASTContext) -> list[Finding]:
        findings: list[Finding] = []
        for assign in context.get_assignments():
            target_low = assign.target.lower()
            is_sensitive_var = any(term in target_low for term in SENSITIVE_VAR_TERMS)
            if not is_sensitive_var:
                continue

            val_str = assign.value_text.strip()
            # If value is a string literal
            if not (
                (val_str.startswith("'") and val_str.endswith("'"))
                or (val_str.startswith('"') and val_str.endswith('"'))
                or (val_str.startswith("`") and val_str.endswith("`"))
            ):
                continue

            clean_val = val_str[1:-1].strip()
            if len(clean_val) < 8:
                continue

            low_val = clean_val.lower()
            if any(ph in low_val for ph in PLACEHOLDER_SUBSTRINGS):
                continue

            # Check entropy and length
            entropy = _shannon_entropy(clean_val)
            has_mixed_chars = (
                any(c.isupper() for c in clean_val)
                and any(c.islower() for c in clean_val)
                and any(c.isdigit() for c in clean_val)
            )

            is_secret = entropy > 3.2 or has_mixed_chars or len(clean_val) >= 20
            if not is_secret:
                continue

            raw_snippet = context.extract_snippet(
                assign.location.line_start,
                assign.location.line_end,
                context_before=1,
                context_after=1,
            )

            # Masked evidence to prevent leaking secrets in reports
            masked_snippet = re.sub(
                r"(['\"][^'\"]{4})[^'\"]+([^'\"]{4}['\"])",
                r"\1...[REDACTED]...\2",
                raw_snippet.content,
            )
            evidence = CodeEvidence(
                content=masked_snippet,
                line_start=raw_snippet.line_start,
                line_end=raw_snippet.line_end,
                highlight_lines=raw_snippet.highlight_lines,
            )

            sig = f"{assign.target}:{assign.location.line_start}"
            fid = Finding.generate_deterministic_id(
                rule_id=self.rule_id,
                file=context.file_path,
                line_start=assign.location.line_start,
                line_end=assign.location.line_end,
                symbol=assign.target,
                evidence_signature=sig,
            )
            fp = Finding.generate_fingerprint(
                rule_id=self.rule_id,
                file=context.file_path,
                symbol=assign.target,
                pattern_signature=sig,
            )

            findings.append(
                Finding(
                    id=fid,
                    fingerprint=fp,
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=self.severity,
                    confidence=self.confidence,
                    file=context.file_path,
                    line_start=assign.location.line_start,
                    line_end=assign.location.line_end,
                    column_start=assign.location.col_start,
                    column_end=assign.location.col_end,
                    symbol=assign.target,
                    title="Hardcoded Secret / Credential Pattern",
                    description=(
                        f"Hardcoded credential assigned to '{assign.target}' in '{context.file_path}'. "
                        "Static secrets in version control risk credential compromise."
                    ),
                    evidence=evidence,
                    impact="Credentials committed to source control are accessible to all repository readers.",
                    recommendation="Extract credential to an external environment variable or secure secrets manager.",
                )
            )

        return findings


class JSInsecureSecretFallbackRule:
    """ENT-LOG-JS-003: Insecure Secret Fallback in Environment Lookup."""

    rule_id = "ENT-LOG-JS-003"
    name = "Inconsistent Secret Fallback in Environment Lookup"
    category = DebtCategory.LOGGING_AND_SECRETS
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM

    @property
    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            rule_id=self.rule_id,
            category=self.category,
            title=self.name,
            description="Environment variable representing a secret falls back to a hardcoded string literal.",
            default_severity=self.severity,
            default_confidence=self.confidence,
            languages=[SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
            impact_template="If the environment variable is omitted or misconfigured, the application runs with an insecure default credential.",
            recommendation_template="Fail fast if critical environment variables are absent rather than falling back to hardcoded secrets.",
            rationale="Fallback defaults for credentials mask missing configuration and weaken deployment security.",
        )

    def analyze(self, context: JSTSASTContext) -> list[Finding]:
        findings: list[Finding] = []
        for assign in context.get_assignments():
            if not assign.is_env_access or not assign.env_var_name or not assign.fallback_text:
                continue

            env_name = assign.env_var_name.lower()
            # False-positive safeguard: standard config variables like PORT or NODE_ENV
            if env_name in CONFIG_ENV_VARS or "port" in env_name or "host" in env_name:
                continue

            # Must indicate a sensitive credential
            is_sensitive_env = any(term in env_name for term in SENSITIVE_VAR_TERMS)
            if not is_sensitive_env:
                continue

            # Fallback must be a string literal, not a number or boolean
            fb = assign.fallback_text.strip()
            if not (
                (fb.startswith("'") and fb.endswith("'"))
                or (fb.startswith('"') and fb.endswith('"'))
                or (fb.startswith("`") and fb.endswith("`"))
            ):
                continue

            snippet = context.extract_snippet(
                assign.location.line_start,
                assign.location.line_end,
                context_before=1,
                context_after=1,
            )

            sig = f"{assign.env_var_name}:{assign.location.line_start}"
            fid = Finding.generate_deterministic_id(
                rule_id=self.rule_id,
                file=context.file_path,
                line_start=assign.location.line_start,
                line_end=assign.location.line_end,
                symbol=assign.env_var_name,
                evidence_signature=sig,
            )
            fp = Finding.generate_fingerprint(
                rule_id=self.rule_id,
                file=context.file_path,
                symbol=assign.env_var_name,
                pattern_signature=sig,
            )

            findings.append(
                Finding(
                    id=fid,
                    fingerprint=fp,
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=self.severity,
                    confidence=self.confidence,
                    file=context.file_path,
                    line_start=assign.location.line_start,
                    line_end=assign.location.line_end,
                    column_start=assign.location.col_start,
                    column_end=assign.location.col_end,
                    symbol=assign.env_var_name,
                    title="Inconsistent Secret Fallback in Environment Lookup",
                    description=(
                        f"Environment secret lookup 'process.env.{assign.env_var_name}' in '{context.file_path}' "
                        f"falls back to static default '{assign.fallback_text}'."
                    ),
                    evidence=snippet,
                    impact="Application operates with predictable or weak default secrets if configuration fails.",
                    recommendation="Enforce mandatory environment variable presence and abort startup on missing secrets.",
                )
            )

        return findings

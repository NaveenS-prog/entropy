"""Domain models for Logging and Secret Handling Debt Analyzer."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from app.models.domain.enums import Confidence
from app.parser.python.models import SourceLocation


class SecretKind(StrEnum):
    """Categorization of detected secrets."""

    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    PRIVATE_KEY = "private_key"
    CREDENTIAL = "credential"
    FALLBACK_SECRET = "fallback_secret"


class LoggingEvidenceKind(StrEnum):
    """Mechanisms through which sensitive data enters logging pipelines."""

    SENSITIVE_VARIABLE_ARG = "sensitive_variable_arg"
    SENSITIVE_FSTRING_INTERPOLATION = "sensitive_fstring_interpolation"
    SENSITIVE_KEYWORD_ARG = "sensitive_keyword_arg"
    SENSITIVE_OBJECT_LOG = "sensitive_object_log"


@dataclass(frozen=True)
class SecretEvidence:
    """Observable evidence of hardcoded secret or inconsistent secret retrieval."""

    source_location: SourceLocation
    variable_name: str
    secret_kind: SecretKind
    confidence: Confidence
    details: str
    pattern_signature: str


@dataclass(frozen=True)
class LoggingEvidence:
    """Observable evidence of sensitive data or objects being logged."""

    source_location: SourceLocation
    logger_name: str
    method_name: str
    evidence_kind: LoggingEvidenceKind
    sensitive_identifier: str
    confidence: Confidence
    details: str
    pattern_signature: str

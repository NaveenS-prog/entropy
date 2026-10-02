"""Domain models for Input Validation Consistency Static Analyzer."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from app.models.domain.enums import Confidence
from app.parser.python.models import SourceLocation


class InputSourceType(StrEnum):
    """Observable mechanisms through which external input is received."""

    FASTAPI_PARAM = "fastapi_param"
    FLASK_REQUEST_JSON = "flask_request_json"
    FLASK_REQUEST_ARGS = "flask_request_args"
    FLASK_REQUEST_FORM = "flask_request_form"
    FLASK_REQUEST_DATA = "flask_request_data"
    DJANGO_REQUEST_GET = "django_request_get"
    DJANGO_REQUEST_POST = "django_request_post"
    DJANGO_REQUEST_DATA = "django_request_data"
    RAW_REQUEST_BODY = "raw_request_body"
    UNKNOWN = "unknown"


class ValidationMechanismType(StrEnum):
    """Observable mechanisms through which input is validated or constrained."""

    PYDANTIC_SCHEMA = "pydantic_schema"
    DRF_SERIALIZER = "drf_serializer"
    DJANGO_FORM = "django_form"
    FIELD_CONSTRAINT = "field_constraint"
    TYPE_CONSTRAINT = "type_constraint"
    EXPLICIT_CHECK = "explicit_check"
    NONE = "none"


@dataclass(frozen=True)
class InputValidationEvidence:
    """Normalized internal representation of observable input validation evidence."""

    source_location: SourceLocation
    endpoint: str
    input_source: InputSourceType
    param_or_field_name: str
    validation_mechanism: ValidationMechanismType
    sink: str | None = None
    confidence: Confidence = Confidence.MEDIUM
    details: str = ""


@dataclass
class EndpointInputProfile:
    """Consolidated input validation profile for an individual endpoint."""

    endpoint_symbol: str
    route_path: str | None
    http_methods: list[str]
    route_group: str
    is_sensitive: bool
    input_sources: list[InputSourceType]
    validation_mechanisms: list[ValidationMechanismType]
    has_schema_validation: bool
    has_unvalidated_input: bool
    unvalidated_evidence: list[InputValidationEvidence]
    sink_evidence: list[InputValidationEvidence]
    metadata: dict[str, Any]

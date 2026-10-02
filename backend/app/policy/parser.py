"""Secure policy configuration parser and validator.

Invariants:
- Uses yaml.safe_load exclusively (no arbitrary Python object deserialization).
- Forbids unknown/extra fields (rejects malicious injection attempts).
- Strictly deterministic; no network access, no shell execution.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from app.policy.models import (
    CategoryRulesConfig,
    FindingRulesConfig,
    PolicyConfig,
    RuleSpecificRulesConfig,
    ScoreRulesConfig,
)


class PolicyConfigurationError(Exception):
    """Raised when policy configuration is malformed, invalid, or violates schema."""

    def __init__(self, message: str, errors: list[dict[str, Any]] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.errors = errors or []


def get_default_policy() -> PolicyConfig:
    """Return the built-in default organizational policy.

    Sensible, production-grade defaults:
    - max_score: 80 (rejects very high debt accumulation)
    - max_delta: 5 (rejects PRs introducing > 5 net points of debt)
    - warn_delta: 2 (warns when PR adds > 2 points)
    - max_new_critical: 0 (zero tolerance for new critical debt)
    - max_new_high: 2 (tolerates at most 2 new high items before failing)
    - max_new: 20 (caps massive debt injections)
    """
    return PolicyConfig(
        name="default",
        description="Default Entropy Architectural and Security Debt Policy",
        enabled=True,
        version="1.0.0",
        score=ScoreRulesConfig(
            max_score=80,
            max_delta=5,
            warn_delta=2,
        ),
        findings=FindingRulesConfig(
            max_new=20,
            max_new_high=2,
            max_new_critical=0,
        ),
        categories=CategoryRulesConfig(),
        rules=RuleSpecificRulesConfig(),
    )


def parse_policy_dict(data: dict[str, Any]) -> PolicyConfig:
    """Validate and parse a raw dictionary into a PolicyConfig model."""
    if not isinstance(data, dict):
        raise PolicyConfigurationError("Policy configuration must be a dictionary/mapping.")

    # Support optional wrapping under top-level 'policy' key
    if "policy" in data and isinstance(data["policy"], dict) and len(data) == 1:
        data = data["policy"]

    try:
        return PolicyConfig.model_validate(data)
    except ValidationError as exc:
        formatted_errors = [
            {"loc": " -> ".join(str(loc) for loc in err["loc"]), "msg": err["msg"], "type": err["type"]}
            for err in exc.errors()
        ]
        msg = f"Policy validation failed with {len(formatted_errors)} error(s): " + "; ".join(
            f"{e['loc']}: {e['msg']}" for e in formatted_errors
        )
        raise PolicyConfigurationError(msg, errors=formatted_errors) from exc


def parse_policy_yaml(content: str) -> PolicyConfig:
    """Parse a YAML or JSON string safely into a PolicyConfig."""
    if not content or not content.strip():
        raise PolicyConfigurationError("Policy content is empty.")

    try:
        raw = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise PolicyConfigurationError(f"Malformed YAML in policy configuration: {exc}") from exc

    if not isinstance(raw, dict):
        raise PolicyConfigurationError("Root of policy document must be an object/mapping.")

    return parse_policy_dict(raw)


def parse_policy_file(path: Path | str) -> PolicyConfig:
    """Load and parse a policy configuration from a local file path."""
    p = Path(path)
    if not p.is_file():
        raise PolicyConfigurationError(f"Policy file not found: {p}")

    try:
        content = p.read_text(encoding="utf-8")
    except Exception as exc:
        raise PolicyConfigurationError(f"Failed to read policy file '{p}': {exc}") from exc

    if p.suffix.lower() == ".json":
        try:
            raw = json.loads(content)
            return parse_policy_dict(raw)
        except json.JSONDecodeError as exc:
            raise PolicyConfigurationError(f"Malformed JSON in policy file '{p}': {exc}") from exc

    return parse_policy_yaml(content)

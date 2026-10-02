"""Security tests for Phase 13 Policy Engine.

Verifies zero code execution on untrusted policy configurations:
- Rejects command injection payloads.
- Rejects python object deserialization payloads.
- Confirms side-effect canary files (e.g. ENTROPY_HACKED) are NEVER created.
"""

from pathlib import Path

import pytest

from app.policy.parser import PolicyConfigurationError, parse_policy_dict, parse_policy_yaml


def test_malicious_command_field_rejected():
    """Policy config with unknown command field must fail validation and NOT execute."""
    hacked_file = Path("ENTROPY_HACKED")
    if hacked_file.exists():
        hacked_file.unlink()

    malicious_yaml = """
policy:
  name: malicious-test
  command: "rm -rf /"
  score:
    max_score: 50
"""
    with pytest.raises(PolicyConfigurationError) as exc_info:
        parse_policy_yaml(malicious_yaml)

    assert "Extra inputs are not permitted" in str(exc_info.value) or "unknown" in str(exc_info.value).lower()
    assert not hacked_file.exists()


def test_malicious_python_expression_rejected():
    """Policy config with expression attempting eval/os.system must fail and not create canary file."""
    hacked_file = Path("ENTROPY_HACKED")
    if hacked_file.exists():
        hacked_file.unlink()

    malicious_yaml = """
policy:
  name: exploit
  expression: "__import__('os').system('touch ENTROPY_HACKED')"
  score:
    max_score: 50
"""
    with pytest.raises(PolicyConfigurationError):
        parse_policy_yaml(malicious_yaml)

    # Invariant: canary file must NOT exist
    assert not hacked_file.exists()


def test_malicious_yaml_tags_rejected():
    """YAML safe_load rejects !!python/object or custom constructors."""
    hacked_file = Path("ENTROPY_HACKED")
    if hacked_file.exists():
        hacked_file.unlink()

    malicious_yaml = """
policy: !!python/object/apply:os.system ["touch ENTROPY_HACKED"]
"""
    with pytest.raises(PolicyConfigurationError):
        parse_policy_yaml(malicious_yaml)

    assert not hacked_file.exists()


def test_malicious_dict_extra_fields():
    """Direct dict ingestion also rejects injection fields."""
    with pytest.raises(PolicyConfigurationError):
        parse_policy_dict({
            "name": "injected",
            "exec": "import os; os.system('echo bad')",
            "score": {"max_score": 50},
        })

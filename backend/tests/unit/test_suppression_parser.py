"""Unit tests for inline suppression parser safety, docstring isolation, and error resilience."""

from pathlib import Path

from app.core.suppression import (
    extract_inline_suppressions,
)


def test_suppression_parser_ignores_docstrings_and_explanatory_comments():
    """Documentation examples in docstrings and comments must not be parsed as suppressions."""
    code = '''"""
This is a module docstring with an example:
# entropy: ignore[RULE-1, RULE-2]
"""

# Pattern for inline suppression: # entropy: ignore[RULE-3] or // entropy: ignore[RULE-4]
# Note: do not use # entropy: ignore[RULE-5] without justification

def foo():
    """Docstring inside function with # entropy: ignore[RULE-6]."""
    pass
'''
    suppressions = extract_inline_suppressions(code, "example.py")
    assert suppressions == [], f"Expected 0 suppressions, got {suppressions}"


def test_suppression_parser_on_suppression_module_itself():
    """Verify that parsing app/core/suppression.py itself extracts zero false suppressions."""
    suppression_file = Path(__file__).resolve().parents[2] / "app" / "core" / "suppression.py"
    code = suppression_file.read_text(encoding="utf-8")
    suppressions = extract_inline_suppressions(code, "app/core/suppression.py")
    assert suppressions == [], f"Expected 0 suppressions in suppression.py itself, got {suppressions}"


def test_bad_suppression_does_not_abort_processing_of_valid_ones(caplog):
    """An invalid/unknown rule ID must not abort parsing of valid suppressions on the same or other lines."""
    code = """
# Line 2 has an invalid rule ID
x = 1  # entropy: ignore[NON_EXISTENT_RULE]

# Line 5 has both an invalid and a valid rule ID
try:
    pass
except Exception:  # entropy: ignore[UNKNOWN_XYZ, ERR-001]
    pass

# Line 11 has a valid rule ID
y = 2  # entropy: ignore[ENT-ERR-001]
"""
    valid_rules = {"ERR-001", "ENT-ERR-001"}
    with caplog.at_level("WARNING"):
        suppressions = extract_inline_suppressions(code, "test.py", valid_rules=valid_rules)

    assert len(suppressions) == 2
    assert suppressions[0].line_number == 8
    assert suppressions[0].rule_ids == ["ERR-001"]
    assert suppressions[1].line_number == 12
    assert suppressions[1].rule_ids == ["ENT-ERR-001"]

    assert "NON_EXISTENT_RULE" in caplog.text
    assert "UNKNOWN_XYZ" in caplog.text

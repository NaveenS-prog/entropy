"""Unit tests for AST parser."""

from pathlib import Path

from app.models.domain.enums import SupportedLanguage
from app.parser.python_ast import PythonAstParser
from app.repository.discoverer import DiscoveredFile


def test_python_ast_parser_valid_file(tmp_path: Path):
    sample = tmp_path / "valid.py"
    sample.write_text("def hello():\n    return 'world'\n")

    discovered = DiscoveredFile(
        absolute_path=sample,
        relative_path="valid.py",
        language=SupportedLanguage.PYTHON,
        size_bytes=len(sample.read_bytes()),
        line_count=2,
    )

    parser = PythonAstParser()
    assert parser.can_parse(SupportedLanguage.PYTHON) is True
    assert parser.can_parse(SupportedLanguage.GO) is False

    parsed = parser.parse(discovered)
    assert parsed.is_valid is True
    assert parsed.ast_root is not None
    assert len(parsed.parse_errors) == 0

    snippet = parsed.extract_snippet(1, 2)
    assert "def hello():" in snippet.content


def test_python_ast_parser_syntax_error(tmp_path: Path):
    sample = tmp_path / "broken.py"
    sample.write_text("def broken(\n")

    discovered = DiscoveredFile(
        absolute_path=sample,
        relative_path="broken.py",
        language=SupportedLanguage.PYTHON,
        size_bytes=len(sample.read_bytes()),
        line_count=1,
    )

    parser = PythonAstParser()
    parsed = parser.parse(discovered)
    assert parsed.is_valid is False
    assert parsed.ast_root is None
    assert len(parsed.parse_errors) > 0
    assert "SyntaxError" in parsed.parse_errors[0]

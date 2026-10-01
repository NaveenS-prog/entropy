"""Unit tests for the resilient Python AST parser."""

from pathlib import Path

from app.models.domain.enums import SupportedLanguage
from app.parser.python.models import ParseStatus
from app.parser.python.parser import PythonParser


def test_valid_python_parsing_from_string():
    parser = PythonParser()
    source = "def add(x: int, y: int) -> int:\n    return x + y\n"
    unit = parser.parse_source(source, file_path="math.py")

    assert unit.is_valid is True
    assert unit.status == ParseStatus.SUCCESS
    assert unit.ast_root is not None
    assert unit.line_count == 2
    assert len(unit.errors) == 0
    assert unit.structure is not None
    assert len(unit.structure.functions) == 1
    fn = unit.structure.functions[0]
    assert fn.name == "add"
    assert fn.return_annotation == "int"
    assert len(fn.parameters) == 2


def test_empty_python_file_parsing(tmp_path: Path):
    parser = PythonParser()
    empty_file = tmp_path / "empty.py"
    empty_file.write_text("")

    unit = parser.parse_file(empty_file, relative_path="empty.py")

    assert unit.is_valid is True
    assert unit.status == ParseStatus.SUCCESS
    assert unit.is_empty is True
    assert unit.line_count == 0
    assert unit.ast_root is not None
    assert len(unit.ast_root.body) == 0
    assert len(unit.errors) == 0
    assert unit.structure is not None
    assert len(unit.structure.functions) == 0


def test_syntax_error_handling(tmp_path: Path):
    parser = PythonParser()
    broken_file = tmp_path / "broken.py"
    broken_file.write_text("def broken(\n    print('hello')\n")

    unit = parser.parse_file(broken_file, relative_path="broken.py")

    assert unit.is_valid is False
    assert unit.status == ParseStatus.SYNTAX_ERROR
    assert unit.ast_root is None
    assert len(unit.errors) == 1
    assert "SyntaxError" in unit.errors[0]
    assert unit.error_location is not None
    assert unit.error_location.line_start == 1


def test_latin1_encoding_detection(tmp_path: Path):
    parser = PythonParser()
    latin1_file = tmp_path / "latin1.py"
    content = b"# -*- coding: latin-1 -*-\n# Auteur: Ren\xe9\ndef nom(): return 'Ren\xe9'\n"
    latin1_file.write_bytes(content)

    unit = parser.parse_file(latin1_file, relative_path="latin1.py")

    assert unit.is_valid is True
    assert unit.status == ParseStatus.SUCCESS
    assert unit.ast_root is not None
    assert len(unit.errors) == 0
    assert "René" in unit.source_code


def test_corrupt_encoding_failure_handling(tmp_path: Path):
    parser = PythonParser()
    corrupt_file = tmp_path / "corrupt.py"
    # Invalid UTF-8 sequence without coding cookie
    corrupt_file.write_bytes(b"# Bad encoding\nx = '\x80\x81\x82'\n")

    unit = parser.parse_file(corrupt_file, relative_path="corrupt.py")

    assert unit.is_valid is False
    assert unit.status == ParseStatus.ENCODING_ERROR
    assert unit.ast_root is None
    assert len(unit.errors) == 1
    assert "Encoding error" in unit.errors[0]


def test_non_python_language_rejection(tmp_path: Path):
    parser = PythonParser()
    java_file = tmp_path / "App.java"
    java_file.write_text("public class App {}")

    unit = parser.parse_file(
        java_file,
        relative_path="App.java",
        language=SupportedLanguage.JAVA,
    )

    assert unit.is_valid is False
    assert unit.status == ParseStatus.UNSUPPORTED_LANGUAGE
    assert "analyzer unavailable for Python parser" in unit.errors[0]


def test_missing_file_handling(tmp_path: Path):
    parser = PythonParser()
    missing_file = tmp_path / "nonexistent.py"

    unit = parser.parse_file(missing_file, relative_path="nonexistent.py")

    assert unit.is_valid is False
    assert unit.status == ParseStatus.READ_ERROR
    assert "Failed to read file" in unit.errors[0]


def test_snippet_extraction():
    parser = PythonParser()
    source = (
        "line 1\n"
        "line 2: target start\n"
        "line 3: target middle\n"
        "line 4: target end\n"
        "line 5\n"
    )
    unit = parser.parse_source(source, file_path="test.py")

    snippet = unit.extract_snippet(line_start=2, line_end=4, context_before=1, context_after=1)
    assert snippet.line_start == 1
    assert snippet.line_end == 5
    assert snippet.highlight_lines == [2, 3, 4]
    assert "line 2: target start" in snippet.content
    assert "line 5" in snippet.content

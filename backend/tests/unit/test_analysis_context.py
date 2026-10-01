"""Unit tests for PythonASTContext and repository-level AnalysisContext."""

from pathlib import Path

from app.analyzers.context import AnalysisContext, PythonASTContext
from app.models.domain.enums import SupportedLanguage
from app.parser.base import ParsedFile
from app.parser.python.parser import PythonParser


def test_python_ast_context_enclosing_lookups():
    source = (
        "class OrderManager:\n"          # 1
        "    def __init__(self):\n"       # 2
        "        self.orders = []\n"      # 3
        "\n"                              # 4
        "    def process_order(self):\n"  # 5
        "        def validate():\n"       # 6
        "            x = 1\n"             # 7
        "            return x\n"          # 8
        "        validate()\n"            # 9
        "        return True\n"           # 10
    )
    parser = PythonParser()
    unit = parser.parse_source(source, file_path="orders.py")
    ctx = PythonASTContext(unit)

    # Line 3 is inside OrderManager.__init__
    enclosing_fn = ctx.get_enclosing_function(3)
    assert enclosing_fn is not None
    assert enclosing_fn.name == "__init__"

    enclosing_cls = ctx.get_enclosing_class(3)
    assert enclosing_cls is not None
    assert enclosing_cls.name == "OrderManager"

    # Line 7 is inside inner validate()
    inner_fn = ctx.get_enclosing_function(7)
    assert inner_fn is not None
    assert inner_fn.name == "validate"

    # Line 9 is inside process_order (outside validate)
    outer_fn = ctx.get_enclosing_function(9)
    assert outer_fn is not None
    assert outer_fn.name == "process_order"

    # Line 1 is inside class but not inside a function
    assert ctx.get_enclosing_class(1) is not None
    assert ctx.get_enclosing_function(1) is None


def test_python_ast_context_query_apis():
    source = (
        "import os\n"
        "from typing import Optional\n"
        "\n"
        "@decorator_one\n"
        "def main_func():\n"
        "    try:\n"
        "        os.getenv('API_KEY')\n"
        "    except:\n"
        "        raise RuntimeError('Missing key')\n"
        "    return 42\n"
    )
    parser = PythonParser()
    unit = parser.parse_source(source, file_path="main.py")
    ctx = PythonASTContext(unit)

    # Imports
    assert ctx.has_import("os") is True
    assert ctx.has_import("Optional") is True
    assert ctx.has_import("sys") is False
    assert ctx.get_import("os") is not None

    # Functions
    fn = ctx.get_function("main_func")
    assert fn is not None
    assert fn.location.line_start == 5

    # Calls
    calls = ctx.get_calls("os.getenv")
    assert len(calls) == 1
    assert calls[0].enclosing_function == "main_func"

    # Handlers & Bare excepts
    handlers = ctx.get_exception_handlers()
    assert len(handlers) == 1
    bare = ctx.get_bare_exception_handlers()
    assert len(bare) == 1

    # Raises & Returns
    assert len(ctx.get_raises()) == 1
    assert len(ctx.get_returns()) == 1

    # Decorators
    decs = ctx.get_decorators()
    assert len(decs) == 1
    assert decs[0].name == "decorator_one"

    # Source access
    assert ctx.get_source_line(1) == "import os"
    assert "main_func" in ctx.get_source_range(4, 5)


def test_repository_analysis_context(tmp_path: Path):
    parser = PythonParser()
    valid_unit = parser.parse_source("def hello(): return 'world'\n", file_path="valid.py")
    broken_unit = parser.parse_source("def broken(\n", file_path="broken.py")

    pf_valid = ParsedFile(
        absolute_path=tmp_path / "valid.py",
        relative_path="valid.py",
        language=SupportedLanguage.PYTHON,
        source_code=valid_unit.source_code,
        lines=valid_unit.lines,
        ast_root=valid_unit.ast_root,
        parse_errors=valid_unit.errors,
        structure=valid_unit.structure,
        unit=valid_unit,
    )

    pf_broken = ParsedFile(
        absolute_path=tmp_path / "broken.py",
        relative_path="broken.py",
        language=SupportedLanguage.PYTHON,
        source_code=broken_unit.source_code,
        lines=broken_unit.lines,
        ast_root=broken_unit.ast_root,
        parse_errors=broken_unit.errors,
        structure=broken_unit.structure,
        unit=broken_unit,
    )

    context = AnalysisContext(
        repo_path=tmp_path,
        parsed_files=[pf_valid, pf_broken],
        total_loc=3,
        scanned_file_count=2,
    )

    # Context query tests
    py_ctx = context.get_python_context("valid.py")
    assert py_ctx is not None
    assert py_ctx.is_valid is True
    assert len(py_ctx.get_functions()) == 1

    broken_ctx = context.get_python_context("broken.py")
    assert broken_ctx is not None
    assert broken_ctx.is_valid is False

    valid_contexts = context.get_valid_python_contexts()
    assert len(valid_contexts) == 1
    assert valid_contexts[0].file_path == "valid.py"

    failed_files = context.get_failed_python_files()
    assert len(failed_files) == 1
    assert failed_files[0].relative_path == "broken.py"

    # Backward compatibility tests
    assert len(context.get_files_for_language(SupportedLanguage.PYTHON)) == 1
    assert context.get_file("valid.py") is not None

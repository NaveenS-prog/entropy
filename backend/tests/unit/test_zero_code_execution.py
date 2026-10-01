"""Security verification: Hard proof that Python AST parser NEVER executes repository code."""

from pathlib import Path

from app.parser.python.models import ParseStatus
from app.parser.python.parser import PythonParser


def test_dangerous_decorators_are_never_executed():
    """Verify that parsing code with exploding decorators does NOT execute them."""
    trap_source = (
        "def exploding_decorator(*args, **kwargs):\n"
        "    raise RuntimeError('FATAL: Decorator executed during parsing!')\n"
        "\n"
        "@exploding_decorator('malicious_arg')\n"
        "class MaliciousClass:\n"
        "    pass\n"
        "\n"
        "@exploding_decorator\n"
        "def malicious_function():\n"
        "    raise RuntimeError('FATAL: Function executed during parsing!')\n"
    )

    parser = PythonParser()
    # If the parser executed the decorator, RuntimeError would be raised here
    unit = parser.parse_source(trap_source, file_path="trap.py")

    assert unit.is_valid is True
    assert unit.status == ParseStatus.SUCCESS
    assert len(unit.structure.classes) == 1
    assert len(unit.structure.functions) == 2

    # Decorator metadata is extracted purely as static AST
    cls = unit.structure.classes[0]
    assert len(cls.decorators) == 1
    assert cls.decorators[0].name == "exploding_decorator"
    assert cls.decorators[0].arguments == ["'malicious_arg'"]


def test_system_calls_and_executables_are_never_executed(tmp_path: Path):
    """Verify that parsing code attempting to touch files or run commands never executes."""
    trap_marker = tmp_path / "trapped_marker.txt"
    if trap_marker.exists():
        trap_marker.unlink()

    trap_code = (
        f"import os\n"
        f"os.system('touch {trap_marker}')\n"
        f"with open('{trap_marker}', 'w') as f:\n"
        f"    f.write('EXPLOITED')\n"
    )

    trap_file = tmp_path / "exploit.py"
    trap_file.write_text(trap_code)

    parser = PythonParser()
    unit = parser.parse_file(trap_file, relative_path="exploit.py")

    assert unit.is_valid is True
    assert unit.status == ParseStatus.SUCCESS

    # The filesystem marker must NEVER have been created
    assert trap_marker.exists() is False


def test_import_side_effects_are_never_triggered(tmp_path: Path):
    """Verify that imports in scanned files are not loaded into Python sys.modules."""
    import sys

    bogus_module_name = "definitely_nonexistent_custom_repo_pkg_12345"
    code = f"import {bogus_module_name}\nfrom {bogus_module_name} import secret_value\n"

    parser = PythonParser()
    unit = parser.parse_source(code, file_path="unimported.py")

    assert unit.is_valid is True
    assert unit.status == ParseStatus.SUCCESS
    assert len(unit.structure.imports) == 2
    assert bogus_module_name not in sys.modules

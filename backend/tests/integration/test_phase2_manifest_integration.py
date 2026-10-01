"""Integration tests verifying Phase 1 Manifest feeding into Phase 2 Python AST engine."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.models.domain.enums import ScanStatus
from app.parser.python.models import ParseStatus
from app.services.repository_service import repository_service

client = TestClient(app)


def test_manifest_feeds_python_files_into_phase2_engine():
    fixture_dir = Path(__file__).resolve().parent.parent / "fixtures" / "python_ast_fixture"

    # Step 1: Phase 1 repository scan
    scan = repository_service.execute_scan(repo_path=str(fixture_dir), repo_name="ast-fixture-repo")

    assert scan.status == ScanStatus.COMPLETED
    assert scan.manifest is not None
    assert scan.manifest.repository.source_files >= 6

    # Step 2: Phase 2 AST parsing from manifest
    units = repository_service.parse_python_files(scan.scan_id)
    assert len(units) >= 6

    # Find specific units
    simple_unit = next((u for u in units if u.file_path == "simple_module.py"), None)
    assert simple_unit is not None
    assert simple_unit.status == ParseStatus.SUCCESS
    assert simple_unit.is_valid is True
    assert len(simple_unit.structure.functions) == 1
    assert simple_unit.structure.functions[0].name == "get_version"

    # Verify broken file handled safely without stopping the scan
    broken_unit = next((u for u in units if u.file_path == "syntax_error.py"), None)
    assert broken_unit is not None
    assert broken_unit.status == ParseStatus.SYNTAX_ERROR
    assert broken_unit.is_valid is False
    assert len(broken_unit.errors) > 0


def test_non_python_files_are_not_passed_to_python_parser():
    mixed_dir = Path(__file__).resolve().parent.parent / "fixtures" / "mixed_language_project"

    # Step 1: Scan mixed repository
    scan = repository_service.execute_scan(repo_path=str(mixed_dir), repo_name="mixed-repo")
    assert scan.status == ScanStatus.COMPLETED
    assert scan.manifest is not None

    # Step 2: Parse Python files
    units = repository_service.parse_python_files(scan.scan_id)

    # In mixed_language_project, only backend/app.py is Python
    parsed_paths = [u.file_path for u in units]
    assert "backend/app.py" in parsed_paths

    # Verify NO non-Python files were parsed as Python
    for path in parsed_paths:
        assert path.endswith(".py")
    assert "services/Billing.java" not in parsed_paths
    assert "core/engine.cpp" not in parsed_paths
    assert "types/api.ts" not in parsed_paths
    assert "cli/src/main.rs" not in parsed_paths


def test_ast_inspection_api_endpoints():
    fixture_dir = Path(__file__).resolve().parent.parent / "fixtures" / "python_ast_fixture"

    # Trigger scan via API
    resp = client.post(
        "/api/v1/repositories/scan",
        json={"path": str(fixture_dir), "repo_name": "api-ast-test"},
    )
    assert resp.status_code == 201
    scan_id = resp.json()["scan_id"]

    # 1. Inspect AST summary endpoint
    summary_resp = client.get(f"/api/v1/scans/{scan_id}/ast")
    assert summary_resp.status_code == 200
    summary_data = summary_resp.json()
    assert isinstance(summary_data, list)
    assert len(summary_data) >= 6

    # 2. Inspect specific file AST structure
    detail_resp = client.get(f"/api/v1/scans/{scan_id}/ast/simple_module.py")
    assert detail_resp.status_code == 200
    detail_data = detail_resp.json()
    assert detail_data["file_path"] == "simple_module.py"
    assert detail_data["is_valid"] is True
    assert detail_data["status"] == "SUCCESS"
    assert len(detail_data["structure"]["functions"]) == 1
    assert detail_data["structure"]["functions"][0]["name"] == "get_version"
    assert len(detail_data["structure"]["imports"]) >= 3


def test_determinism_same_source_yields_identical_ast():
    fixture_file = (
        Path(__file__).resolve().parent.parent
        / "fixtures"
        / "python_ast_fixture"
        / "classes_and_methods.py"
    )

    from app.parser.python.parser import PythonParser

    p = PythonParser()
    unit1 = p.parse_file(fixture_file, relative_path="classes_and_methods.py")
    unit2 = p.parse_file(fixture_file, relative_path="classes_and_methods.py")

    assert unit1.status == unit2.status
    assert unit1.line_count == unit2.line_count
    assert len(unit1.structure.classes) == len(unit2.structure.classes)
    assert len(unit1.structure.functions) == len(unit2.structure.functions)
    assert len(unit1.structure.all_calls) == len(unit2.structure.all_calls)

    cls1 = unit1.structure.classes[0]
    cls2 = unit2.structure.classes[0]
    assert cls1.name == cls2.name
    assert cls1.location == cls2.location
    assert cls1.decorators == cls2.decorators

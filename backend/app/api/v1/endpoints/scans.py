"""Endpoints for initiating and querying repository scans."""

from pathlib import Path

from fastapi import APIRouter, HTTPException, status

from app.comparison.models import ScanComparisonResult
from app.comparison.service import comparison_service
from app.models.domain.manifest import RepositoryManifest
from app.schemas.scan_schemas import ScanCreateRequest, ScanDetailResponse, ScanSummaryResponse
from app.services.repository_service import repository_service
from app.services.scan_service import scan_service

router = APIRouter()


@router.post("", response_model=ScanDetailResponse, status_code=status.HTTP_201_CREATED)
def trigger_scan(request: ScanCreateRequest) -> ScanDetailResponse:
    """Execute repository scan, file discovery, language classification, and manifest generation."""
    target = request.target_path
    scan_result = repository_service.execute_scan(
        repo_path=target,
        repo_name=request.repo_name,
    )
    return ScanDetailResponse(
        scan_id=scan_result.scan_id,
        repository=scan_result.repository,
        status=scan_result.status,
        manifest=scan_result.manifest,
        findings=scan_result.findings,
        score=scan_result.score,
        started_at=scan_result.started_at,
        completed_at=scan_result.completed_at,
        duration_ms=scan_result.duration_ms,
        analyzers_executed=scan_result.analyzers_executed,
        errors=scan_result.errors,
    )


@router.get("", response_model=list[ScanSummaryResponse])
def list_scans() -> list[ScanSummaryResponse]:
    """Retrieve all completed scans."""
    scans = scan_service.list_scans()
    scans = repository_service.list_scans()
    return [
        ScanSummaryResponse(
            scan_id=s.scan_id,
            repo_name=s.repository.name,
            repo_path=s.repository.path,
            branch=s.repository.branch,
            commit_hash=s.repository.commit_hash,
            status=s.status,
            total_score=s.score.total_score if s.score else None,
            tier=s.score.tier if s.score else None,
            total_findings=len(s.findings),
            total_loc=s.repository.total_loc,
            analyzed_files=s.score.analyzed_files if s.score else 0,
            started_at=s.started_at,
            duration_ms=s.duration_ms,
        )
        for s in scans
    ]


@router.get("/{scan_id}", response_model=ScanDetailResponse)
def get_scan(scan_id: str) -> ScanDetailResponse:
    """Retrieve full details of a specific scan by its ID."""
    scan_result = repository_service.get_scan(scan_id)
    if not scan_result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found",
        )

    return ScanDetailResponse(
        scan_id=scan_result.scan_id,
        repository=scan_result.repository,
        status=scan_result.status,
        manifest=scan_result.manifest,
        findings=scan_result.findings,
        score=scan_result.score,
        started_at=scan_result.started_at,
        completed_at=scan_result.completed_at,
        duration_ms=scan_result.duration_ms,
        analyzers_executed=scan_result.analyzers_executed,
        errors=scan_result.errors,
    )


@router.get("/{scan_id}/manifest", response_model=RepositoryManifest)
def get_scan_manifest(scan_id: str) -> RepositoryManifest:
    """Retrieve the repository manifest for a scan."""
    manifest = repository_service.get_manifest(scan_id)
    if not manifest:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Manifest for scan '{scan_id}' not found",
        )
    return manifest


@router.get("/{scan_id}/ast")
def get_scan_ast_summary(scan_id: str) -> list[dict]:
    """Retrieve summary of all parsed Python AST units for a scan."""
    scan = repository_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found",
        )
    py_units = repository_service.parse_python_files(scan_id)
    js_units = repository_service.parse_jsts_files(scan_id)
    return [u.to_summary_dict() for u in py_units] + [u.to_summary_dict() for u in js_units]


@router.get("/{scan_id}/ast/{file_path:path}")
def get_scan_file_ast(scan_id: str, file_path: str) -> dict:
    """Retrieve detailed AST structure for a specific Python, JS, or TS file in a scan."""
    scan = repository_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found",
        )
    unit = repository_service.parse_python_file(scan_id, file_path)
    if unit:
        return {
            "file_path": unit.file_path,
            "language": unit.language.value,
            "status": unit.status.value,
            "line_count": unit.line_count,
            "size_bytes": unit.size_bytes,
            "is_valid": unit.is_valid,
            "is_empty": unit.is_empty,
            "errors": unit.errors,
            "structure": (
                {
                    "docstring": unit.structure.docstring if unit.structure else None,
                    "imports": [
                        {
                            "module": imp.module,
                            "name": imp.name,
                            "alias": imp.alias,
                            "is_from": imp.is_from,
                            "line": imp.location.line_start,
                        }
                        for imp in (unit.structure.imports if unit.structure else [])
                    ],
                    "classes": [
                        {
                            "name": cls.name,
                            "qualified_name": cls.qualified_name,
                            "base_classes": cls.base_classes,
                            "methods_count": len(cls.methods),
                            "docstring": cls.docstring,
                            "line_start": cls.location.line_start,
                            "line_end": cls.location.line_end,
                        }
                        for cls in (unit.structure.classes if unit.structure else [])
                    ],
                    "functions": [
                        {
                            "name": fn.name,
                            "qualified_name": fn.qualified_name,
                            "is_async": fn.is_async,
                            "is_method": fn.is_method,
                            "decorators": [d.name for d in fn.decorators],
                            "parameters": [p.name for p in fn.parameters],
                            "return_annotation": fn.return_annotation,
                            "docstring": fn.docstring,
                            "statement_count": fn.statement_count,
                            "calls_count": len(fn.calls),
                            "handlers_count": len(fn.handlers),
                            "raises_count": len(fn.raises),
                            "returns_count": len(fn.returns),
                            "line_start": fn.location.line_start,
                            "line_end": fn.location.line_end,
                        }
                        for fn in (unit.structure.functions if unit.structure else [])
                    ],
                    "handlers": [
                        {
                            "exception_types": h.exception_types,
                            "name": h.name,
                            "is_bare": h.is_bare,
                            "body_statement_count": h.body_statement_count,
                            "has_pass_only": h.has_pass_only,
                            "enclosing_function": h.enclosing_function,
                            "line_start": h.location.line_start,
                            "line_end": h.location.line_end,
                        }
                        for h in (unit.structure.all_handlers if unit.structure else [])
                    ],
                    "raises": [
                        {
                            "exception_type": r.exception_type,
                            "has_cause": r.has_cause,
                            "cause_type": r.cause_type,
                            "enclosing_function": r.enclosing_function,
                            "line_start": r.location.line_start,
                        }
                        for r in (unit.structure.all_raises if unit.structure else [])
                    ],
                    "calls": [
                        {
                            "callable_name": c.callable_name,
                            "arg_count": c.arg_count,
                            "keyword_args": c.keyword_args,
                            "enclosing_function": c.enclosing_function,
                            "line_start": c.location.line_start,
                        }
                        for c in (unit.structure.all_calls if unit.structure else [])
                    ],
                }
                if unit.structure
                else None
            ),
        }

    js_unit = repository_service.parse_jsts_file(scan_id, file_path)
    if js_unit:
        return {
            "file_path": js_unit.file_path,
            "language": js_unit.language.value,
            "status": js_unit.status.value,
            "line_count": js_unit.line_count,
            "size_bytes": js_unit.size_bytes,
            "is_valid": js_unit.is_valid,
            "is_empty": js_unit.line_count == 0 or len(js_unit.source_code.strip()) == 0,
            "errors": js_unit.errors,
            "structure": (
                {
                    "imports": [
                        {
                            "module": imp.module,
                            "symbols": imp.symbols,
                            "is_require": imp.is_require,
                            "line": imp.location.line_start,
                        }
                        for imp in (js_unit.structure.imports if js_unit.structure else [])
                    ],
                    "exports": [
                        {
                            "name": exp.name,
                            "is_default": exp.is_default,
                            "line": exp.location.line_start,
                        }
                        for exp in (js_unit.structure.exports if js_unit.structure else [])
                    ],
                    "classes": [
                        {
                            "name": cls.name,
                            "base_classes": cls.base_classes,
                            "methods_count": len(cls.methods),
                            "line_start": cls.location.line_start,
                            "line_end": cls.location.line_end,
                        }
                        for cls in (js_unit.structure.classes if js_unit.structure else [])
                    ],
                    "functions": [
                        {
                            "name": fn.name,
                            "qualified_name": fn.qualified_name,
                            "is_async": fn.is_async,
                            "is_arrow": fn.is_arrow,
                            "is_method": fn.is_method,
                            "parameters": fn.parameters,
                            "statement_count": fn.statement_count,
                            "calls_count": len(fn.calls),
                            "handlers_count": len(fn.handlers),
                            "returns_count": len(fn.returns),
                            "line_start": fn.location.line_start,
                            "line_end": fn.location.line_end,
                        }
                        for fn in (js_unit.structure.functions if js_unit.structure else [])
                    ],
                    "handlers": [
                        {
                            "param_name": h.param_name,
                            "is_empty": h.is_empty,
                            "has_logging": h.has_logging,
                            "has_rethrow": h.has_rethrow,
                            "returns_fallback": h.returns_fallback,
                            "fallback_value": h.fallback_value,
                            "statement_count": h.statement_count,
                            "enclosing_function": h.enclosing_function,
                            "line_start": h.location.line_start,
                            "line_end": h.location.line_end,
                        }
                        for h in (js_unit.structure.all_handlers if js_unit.structure else [])
                    ],
                    "calls": [
                        {
                            "callee": c.callee,
                            "method_name": c.method_name,
                            "caller_object": c.caller_object,
                            "arg_count": len(c.arguments),
                            "enclosing_function": c.enclosing_function,
                            "line_start": c.location.line_start,
                        }
                        for c in (js_unit.structure.all_calls if js_unit.structure else [])
                    ],
                    "routes": [
                        {
                            "framework": r.framework,
                            "http_method": r.http_method,
                            "path": r.path,
                            "line_start": r.location.line_start,
                        }
                        for r in (js_unit.structure.routes if js_unit.structure else [])
                    ],
                }
                if js_unit.structure
                else None
            ),
        }

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"File '{file_path}' not found in scan manifest",
    )



@router.post("/sample", response_model=ScanDetailResponse, status_code=status.HTTP_201_CREATED)
def trigger_sample_scan() -> ScanDetailResponse:
    """Trigger a demo scan on the built-in fixture repository.

    Provides instant verification of the end-to-end pipeline without needing
    an external repository.
    """
    fixture_dir = Path(__file__).resolve().parent.parent.parent.parent.parent / "tests" / "fixtures" / "sample_repo"
    fixture_dir = (
        Path(__file__).resolve().parent.parent.parent.parent.parent
        / "tests"
        / "fixtures"
        / "sample_repo"
    )
    if not fixture_dir.exists():
        fixture_dir.mkdir(parents=True, exist_ok=True)
        # Create a sample python file demonstrating authentic debt
        sample_file = fixture_dir / "service.py"
        sample_file.write_text(
            'def handle_payment(payload):\n'
            '    try:\n'
            '        process_token(payload)\n'
            '    except Exception:\n'
            '        pass\n'
            '\n'
            'def fetch_user(user_id):\n'
            '    try:\n'
            '        return db_query(user_id)\n'
            '    except:\n'
            "def handle_payment(payload):\n"
            "    try:\n"
            "        process_token(payload)\n"
            "    except Exception:\n"
            "        pass\n"
            "\n"
            "def fetch_user(user_id):\n"
            "    try:\n"
            "        return db_query(user_id)\n"
            "    except:\n"
            '        print("User query failed")\n'
        )

    scan_result = scan_service.execute_scan(
        repo_path=str(fixture_dir),
        repo_name="sample-ecommerce-service",
    )
    return ScanDetailResponse(
        scan_id=scan_result.scan_id,
        repository=scan_result.repository,
        status=scan_result.status,
        manifest=scan_result.manifest,
        findings=scan_result.findings,
        score=scan_result.score,
        started_at=scan_result.started_at,
        completed_at=scan_result.completed_at,
        duration_ms=scan_result.duration_ms,
        analyzers_executed=scan_result.analyzers_executed,
        errors=scan_result.errors,
    )


@router.get("/{current_scan_id}/compare/{previous_scan_id}", response_model=ScanComparisonResult)
def compare_scans(current_scan_id: str, previous_scan_id: str) -> ScanComparisonResult:
    """Compare two historical scans to identify new, resolved, and persistent debt findings and score deltas."""
    current_scan = repository_service.get_scan(current_scan_id)
    if not current_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Current scan '{current_scan_id}' not found",
        )

    previous_scan = repository_service.get_scan(previous_scan_id)
    if not previous_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Previous scan '{previous_scan_id}' not found",
        )

    # Ensure findings and scores are loaded for both scans
    needs_reload = False
    if not current_scan.analyzers_executed:
        from app.services.analysis_service import analysis_service

        analysis_service.analyze_scan(current_scan_id)
        needs_reload = True
    if current_scan.score is None:
        from app.scoring.service import scoring_service

        scoring_service.calculate_scan_score(current_scan_id)
        needs_reload = True

    if needs_reload:
        current_scan = repository_service.get_scan(current_scan_id) or current_scan

    prev_needs_reload = False
    if not previous_scan.analyzers_executed:
        from app.services.analysis_service import analysis_service

        analysis_service.analyze_scan(previous_scan_id)
        prev_needs_reload = True
    if previous_scan.score is None:
        from app.scoring.service import scoring_service

        scoring_service.calculate_scan_score(previous_scan_id)
        prev_needs_reload = True

    if prev_needs_reload:
        previous_scan = repository_service.get_scan(previous_scan_id) or previous_scan

    return comparison_service.compare_scans(
        current_scan=current_scan, previous_scan=previous_scan
    )


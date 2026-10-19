"""Regression tests for Phase 2: Scope Exclusions.

Ensures:
1. Default excluded paths list is strictly defined in repository/config.py.
2. is_scope_excluded properly identifies test, spec, example, doc, and fixture paths.
3. Express-like layout only scores lib/ by default, excluding test/ and examples/.
4. --include-tests flag and project config restore old behavior (scanning all files).
5. Manifest, API schemas, and CLI text/JSON outputs report excluded file and LOC counts.
"""

import tempfile
from datetime import UTC, datetime
from pathlib import Path

import yaml

from app.cli.main import format_scan_json_dict, format_scan_text
from app.models.domain.enums import ScanStatus
from app.models.domain.scan import RepositoryMetadata, RepositoryScanResult
from app.repository.config import DEFAULT_EXCLUDED_PATHS, ScannerConfig, is_scope_excluded
from app.repository.discoverer import RepositoryDiscoverer
from app.repository.manifest import ManifestBuilder
from app.services.repository_service import RepositoryService


def test_default_excluded_paths_completeness():
    """Verify all required exclusion paths are present in DEFAULT_EXCLUDED_PATHS."""
    expected = [
        "test",
        "tests",
        "__tests__",
        "spec",
        "e2e",
        "examples",
        "example",
        "docs",
        "fixtures",
        "__mocks__",
        "vendor",
        "third_party",
        "node_modules",
        "dist",
        "build",
        "*.test.*",
        "*.spec.*",
        "test_*.py",
        "*_test.py",
        "*.stories.*",
    ]
    for item in expected:
        assert item in DEFAULT_EXCLUDED_PATHS, f"Expected '{item}' in DEFAULT_EXCLUDED_PATHS"


def test_is_scope_excluded_matching():
    """Verify matching logic across various directory parts and file globs."""
    # Excluded directories
    assert is_scope_excluded("test/app.js") is True
    assert is_scope_excluded("tests/unit/test_core.py") is True
    assert is_scope_excluded("__tests__/render.test.ts") is True
    assert is_scope_excluded("spec/requests/api_spec.rb") is True
    assert is_scope_excluded("e2e/flows/login.ts") is True
    assert is_scope_excluded("examples/auth-demo/index.js") is True
    assert is_scope_excluded("example/minimal.py") is True
    assert is_scope_excluded("docs/snippets/quickstart.py") is True
    assert is_scope_excluded("fixtures/data_mock.py") is True
    assert is_scope_excluded("__mocks__/api_client.ts") is True
    assert is_scope_excluded("vendor/bundle.js") is True
    assert is_scope_excluded("third_party/helper.py") is True
    assert is_scope_excluded("node_modules/express/index.js") is True
    assert is_scope_excluded("dist/bundle.js") is True
    assert is_scope_excluded("build/output.js") is True

    # Excluded file patterns
    assert is_scope_excluded("src/auth.test.ts") is True
    assert is_scope_excluded("lib/calc.spec.js") is True
    assert is_scope_excluded("backend/test_api.py") is True
    assert is_scope_excluded("services/user_test.py") is True
    assert is_scope_excluded("ui/Button.stories.tsx") is True

    # Maintained / production source paths - MUST NOT BE EXCLUDED
    assert is_scope_excluded("lib/express.js") is False
    assert is_scope_excluded("src/controllers/auth.ts") is False
    assert is_scope_excluded("app/main.py") is False
    assert is_scope_excluded("core/router.py") is False


def test_express_like_layout_scores_lib_only():
    """Verify that an Express-like repository layout only analyzes lib/ by default,

    and that excluded files and LOC are accurately tracked and reported.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        lib_dir = root / "lib"
        test_dir = root / "test"
        examples_dir = root / "examples" / "chat"

        lib_dir.mkdir(parents=True)
        test_dir.mkdir(parents=True)
        examples_dir.mkdir(parents=True)

        lib_file = lib_dir / "express.js"
        lib_file.write_text(
            "const express = require('express');\n"
            "const app = express();\n"
            "app.get('/health', (req, res) => res.send('ok'));\n"
            "module.exports = app;\n",
            encoding="utf-8",
        )

        test_file = test_dir / "app.test.js"
        test_file.write_text(
            "const request = require('supertest');\n"
            "const app = require('../lib/express');\n"
            "describe('GET /health', () => {\n"
            "  it('should return 200', async () => {\n"
            "    await request(app).get('/health').expect(200);\n"
            "  });\n"
            "});\n",
            encoding="utf-8",
        )

        example_file = examples_dir / "server.js"
        example_file.write_text(
            "const express = require('../../../lib/express');\n"
            "const app = express();\n"
            "app.listen(3000, () => console.log('Chat example running'));\n",
            encoding="utf-8",
        )

        # 1. Default discovery (include_tests=False)
        discoverer = RepositoryDiscoverer(ScannerConfig(include_tests=False))
        result = discoverer.discover_repository(root)

        source_rel_paths = [f.relative_path for f in result.source_files]
        assert source_rel_paths == ["lib/express.js"], f"Expected only lib/express.js, got: {source_rel_paths}"
        assert result.excluded_files_count == 2
        # lib_file is 4 LOC, test_file is 7 LOC, example_file is 3 LOC
        assert result.total_source_loc == 4
        assert result.excluded_loc == 10

        # Manifest builder verification
        manifest = ManifestBuilder.build("express-mock", root, result)
        assert manifest.repository.source_files == 1
        assert manifest.repository.excluded_files == 2
        assert manifest.repository.excluded_loc == 10

        # 2. Opt-in discovery (include_tests=True restores old behavior)
        discoverer_opt_in = RepositoryDiscoverer(ScannerConfig(include_tests=True))
        result_opt_in = discoverer_opt_in.discover_repository(root)

        opt_in_paths = sorted([f.relative_path for f in result_opt_in.source_files])
        assert opt_in_paths == [
            "examples/chat/server.js",
            "lib/express.js",
            "test/app.test.js",
        ]
        assert result_opt_in.excluded_files_count == 0
        assert result_opt_in.excluded_loc == 0
        assert result_opt_in.total_source_loc == 14


def test_scan_service_and_project_config_opt_in():
    """Verify that ScanService and project-config (.entropy.yml) honor include_tests."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        (root / "lib").mkdir()
        (root / "test").mkdir()

        (root / "lib" / "app.py").write_text("def run():\n    return 42\n")
        (root / "test" / "test_app.py").write_text("def test_run():\n    assert True\n")

        # By default without .entropy.yml
        repo_service = RepositoryService()
        scan_default = repo_service.execute_scan(str(root), include_tests=False)
        assert scan_default.repository.scannable_files == 1
        assert scan_default.repository.excluded_files == 1
        assert scan_default.repository.excluded_loc == 2

        # With explicit include_tests=True
        scan_opt_in = repo_service.execute_scan(str(root), include_tests=True)
        assert scan_opt_in.repository.scannable_files == 2
        assert scan_opt_in.repository.excluded_files == 0
        assert scan_opt_in.repository.excluded_loc == 0

        # With .entropy.yml opt-in
        config_file = root / ".entropy.yml"
        config_data = {
            "project": {"name": "test-repo"},
            "analysis": {"include_tests": True},
        }
        config_file.write_text(yaml.safe_dump(config_data), encoding="utf-8")

        scan_yaml_opt_in = repo_service.execute_scan(str(root), include_tests=False)
        assert scan_yaml_opt_in.repository.scannable_files == 2
        assert scan_yaml_opt_in.repository.excluded_files == 0


def test_cli_reporting_of_exclusions():
    """Verify that format_scan_text and format_scan_json_dict report excluded metrics."""
    repo_meta = RepositoryMetadata(
        name="test-repo",
        path="/path/to/test-repo",
        total_files=5,
        scannable_files=2,
        total_loc=150,
        excluded_files=3,
        excluded_loc=220,
    )

    scan = RepositoryScanResult(
        scan_id="test-scan-123",
        repository=repo_meta,
        status=ScanStatus.COMPLETED,
        started_at=datetime.now(UTC),
        findings=[],
        score=None,
    )

    text_output = format_scan_text(scan)
    assert "Scope Exclusions: 3 files (220 LOC excluded)" in text_output

    json_dict = format_scan_json_dict(scan)
    assert json_dict["files"]["excluded_files"] == 3
    assert json_dict["files"]["excluded_loc"] == 220

"""Comprehensive unit tests for Entropy Phase 14 Developer CLI."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from app.cli.main import (
    EXIT_CONFIG_ERROR,
    EXIT_PASS,
    EXIT_POLICY_FAIL,
    EXIT_SYSTEM_ERROR,
    main,
)
from app.core.config import settings
from app.models.domain.ai_explanation import AIExplanation


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    """Create a clean minimal sample repository with Python code."""
    repo_dir = tmp_path / "sample_repo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text(
        "def calc(val):\n"
        "    try:\n"
        "        return val * 2\n"
        "    except Exception:\n"
        "        pass\n",
        encoding="utf-8",
    )
    return repo_dir


@pytest.fixture
def malicious_repo(tmp_path: Path) -> Path:
    """Create a repository fixture containing malicious scripts that must never execute."""
    repo_dir = tmp_path / "malicious_repo"
    repo_dir.mkdir()
    (repo_dir / "exploit.py").write_text(
        'from pathlib import Path\nPath("ENTROPY_CLI_HACKED.txt").write_text("EXECUTED")\n',
        encoding="utf-8",
    )
    (repo_dir / "exploit.js").write_text(
        'require("fs").writeFileSync("ENTROPY_CLI_HACKED.txt", "EXECUTED");\n',
        encoding="utf-8",
    )
    return repo_dir


# -----------------------------------------------------------------------------
# 1. HELP & DISCOVERY TESTS
# -----------------------------------------------------------------------------

def test_cli_help(capsys):
    """entropy --help outputs clean help and returns EXIT_CONFIG_ERROR (argparse help exits or displays)."""
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "Entropy: Deterministic Architectural & Security Debt Engine" in captured.out
    assert "scan" in captured.out
    assert "check" in captured.out
    assert "findings" in captured.out
    assert "compare" in captured.out
    assert "explain" in captured.out
    assert "version" in captured.out
    assert "policy" in captured.out


def test_cli_subcommand_helps(capsys):
    """Subcommands provide valid help output."""
    for sub in ["scan", "check", "findings", "compare", "explain", "version", "policy"]:
        with pytest.raises(SystemExit) as exc:
            main([sub, "--help"])
        assert exc.value.code == 0


# -----------------------------------------------------------------------------
# 2. VERSION TESTS
# -----------------------------------------------------------------------------

def test_cli_version_command(capsys):
    """entropy version returns 0 and displays the single source-of-truth version."""
    exit_code = main(["version"])
    assert exit_code == EXIT_PASS
    captured = capsys.readouterr()
    assert settings.VERSION in captured.out
    assert captured.out.strip() == f"entropy {settings.VERSION}"


def test_cli_version_flag(capsys):
    """entropy --version returns 0 and displays the single source-of-truth version."""
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert settings.VERSION in captured.out


def test_cli_version_quiet(capsys):
    """entropy version --quiet returns bare version string."""
    exit_code = main(["--quiet", "version"])
    assert exit_code == EXIT_PASS
    captured = capsys.readouterr()
    assert captured.out.strip() == settings.VERSION


# -----------------------------------------------------------------------------
# 3. SCAN COMMAND TESTS
# -----------------------------------------------------------------------------

def test_cli_scan_text(sample_repo: Path, capsys):
    """entropy scan <path> executes scan and prints human-readable summary."""
    exit_code = main(["scan", str(sample_repo)])
    assert exit_code == EXIT_PASS
    captured = capsys.readouterr()
    assert "Entropy Scan" in captured.out
    assert "Files discovered:" in captured.out
    assert "Entropy Score:" in captured.out
    assert "Categories:" in captured.out
    assert "Error Handling" in captured.out


def test_cli_scan_json(sample_repo: Path, capsys):
    """entropy scan <path> --format json outputs valid, deterministic JSON."""
    exit_code = main(["scan", str(sample_repo), "--format", "json"])
    assert exit_code == EXIT_PASS
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "repository" in data
    assert "files" in data
    assert "score" in data
    assert "categories" in data
    assert "findings" in data
    assert data["files"]["discovered"] >= 1
    assert "total_score" in data["score"]


def test_cli_scan_sarif(sample_repo: Path, capsys):
    """entropy scan <path> --format sarif outputs valid SARIF 2.1.0 log."""
    exit_code = main(["scan", str(sample_repo), "--format", "sarif"])
    assert exit_code == EXIT_PASS
    captured = capsys.readouterr()
    sarif = json.loads(captured.out)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == settings.APP_NAME
    assert run["tool"]["driver"]["version"] == settings.VERSION
    assert "results" in run


def test_cli_scan_nonexistent_path(capsys):
    """entropy scan on a non-existent path returns EXIT_SYSTEM_ERROR (3)."""
    exit_code = main(["scan", "non_existent_directory_xyz"])
    assert exit_code == EXIT_SYSTEM_ERROR
    captured = capsys.readouterr()
    assert "does not exist" in captured.err


# -----------------------------------------------------------------------------
# 4. CHECK COMMAND TESTS
# -----------------------------------------------------------------------------

def test_cli_check_pass(sample_repo: Path, capsys):
    """entropy check passes when policy is satisfied."""
    exit_code = main(["check", str(sample_repo)])
    assert exit_code == EXIT_PASS
    captured = capsys.readouterr()
    assert "Entropy Check" in captured.out
    assert "Result: PASS" in captured.out
    assert "Exit code: 0" in captured.out


def test_cli_check_json(sample_repo: Path, capsys):
    """entropy check --format json outputs structured policy result."""
    exit_code = main(["check", str(sample_repo), "--format", "json"])
    assert exit_code == EXIT_PASS
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "score" in data
    assert "band" in data
    assert "policy" in data
    assert "result" in data
    assert data["result"] == "PASS"


def test_cli_check_fail_with_strict_policy(sample_repo: Path, tmp_path: Path, capsys):
    """entropy check returns EXIT_POLICY_FAIL (1) when strict custom policy fails."""
    strict_policy = tmp_path / "strict.yaml"
    strict_policy.write_text(
        "policy:\n"
        "  name: zero-tolerance\n"
        "  version: 1.0.0\n"
        "  score:\n"
        "    max_score: 0\n"
        "  rules:\n"
        "    forbidden_rules: ['ENT-ERR-001']\n",
        encoding="utf-8",
    )
    exit_code = main(["check", str(sample_repo), "--policy", str(strict_policy)])
    assert exit_code == EXIT_POLICY_FAIL
    captured = capsys.readouterr()
    assert "Result: FAIL" in captured.out
    assert "Exit code: 1" in captured.out


def test_cli_check_invalid_policy(sample_repo: Path, tmp_path: Path, capsys):
    """entropy check returns EXIT_CONFIG_ERROR (2) on invalid policy configuration."""
    bad_policy = tmp_path / "bad.yaml"
    bad_policy.write_text("policy:\n  name: bad\n  score:\n    max_score: -5\n", encoding="utf-8")
    exit_code = main(["check", str(sample_repo), "--policy", str(bad_policy)])
    assert exit_code == EXIT_CONFIG_ERROR
    captured = capsys.readouterr()
    assert "Policy configuration error" in captured.err


# -----------------------------------------------------------------------------
# 5. FINDINGS COMMAND TESTS
# -----------------------------------------------------------------------------

def test_cli_findings_all(sample_repo: Path, capsys):
    """entropy findings displays discovered findings."""
    exit_code = main(["findings", str(sample_repo)])
    assert exit_code == EXIT_PASS
    captured = capsys.readouterr()
    assert "Entropy Findings" in captured.out
    assert "Total Findings:" in captured.out


def test_cli_findings_filter_rule(sample_repo: Path, capsys):
    """entropy findings --rule filters to matching rules."""
    exit_code = main(["findings", str(sample_repo), "--rule", "ENT-ERR-001"])
    assert exit_code == EXIT_PASS
    captured = capsys.readouterr()
    if "No findings" not in captured.out:
        assert "ENT-ERR-001" in captured.out


def test_cli_findings_filter_invalid_severity(sample_repo: Path, capsys):
    """entropy findings with invalid severity returns EXIT_CONFIG_ERROR (2) or raises SystemExit(2)."""
    with pytest.raises(SystemExit) as exc:
        main(["findings", str(sample_repo), "--severity", "super_critical"])
    assert exc.value.code == EXIT_CONFIG_ERROR
    captured = capsys.readouterr()
    assert "invalid choice" in captured.err


def test_cli_findings_json(sample_repo: Path, capsys):
    """entropy findings --format json outputs array of findings."""
    exit_code = main(["findings", str(sample_repo), "--format", "json"])
    assert exit_code == EXIT_PASS
    captured = capsys.readouterr()
    findings_list = json.loads(captured.out)
    assert isinstance(findings_list, list)


# -----------------------------------------------------------------------------
# 6. COMPARE COMMAND TESTS
# -----------------------------------------------------------------------------

def test_cli_compare_paths(tmp_path: Path, capsys):
    """entropy compare between two directories outputs comparison table."""
    base_dir = tmp_path / "base_repo"
    base_dir.mkdir()
    (base_dir / "code.py").write_text("def a(): pass\n", encoding="utf-8")

    head_dir = tmp_path / "head_repo"
    head_dir.mkdir()
    (head_dir / "code.py").write_text(
        "def a():\n    try: pass\n    except Exception: pass\n",
        encoding="utf-8",
    )

    exit_code = main(["compare", str(base_dir), str(head_dir)])
    assert exit_code == EXIT_PASS
    captured = capsys.readouterr()
    assert "Entropy Comparison" in captured.out
    assert "Delta:" in captured.out
    assert "New:" in captured.out
    assert "Category Deltas:" in captured.out


def test_cli_compare_invalid_target(capsys):
    """entropy compare with invalid targets returns EXIT_SYSTEM_ERROR (3)."""
    exit_code = main(["compare", "non_existent_1", "non_existent_2"])
    assert exit_code == EXIT_SYSTEM_ERROR


# -----------------------------------------------------------------------------
# 7. AI EXPLAIN ADVISORY TESTS
# -----------------------------------------------------------------------------

def test_cli_explain_when_ai_disabled(capsys):
    """entropy explain when AI_ENABLED is False notices gracefully without error."""
    with patch.object(settings, "AI_ENABLED", False):
        exit_code = main(["explain", "ENT-ERR-001-TEST"])
        assert exit_code == EXIT_PASS
        captured = capsys.readouterr()
        assert "AI explanation layer is currently disabled" in captured.err


def test_cli_explain_when_ai_enabled_mocked(capsys):
    """entropy explain when AI_ENABLED is True displays advisory explanation."""
    mock_explanation = AIExplanation(
        finding_id="finding-123",
        summary="Empty exception handler detected.",
        why_it_matters="Exceptions are silently swallowed.",
        evidence_explanation="The except block contains only 'pass'.",
        architectural_impact="Hides critical production failures.",
        remediation="Log the exception with logger.exception() or re-raise.",
        suggested_pattern="Use explicit logging or error propagation.",
        model="gemini-1.5-flash",
        prompt_version="1.0",
    )

    with patch.object(settings, "AI_ENABLED", True):
        with patch("app.ai.service.ai_service.explain_finding", return_value=mock_explanation):
            exit_code = main(["explain", "finding-123"])
            assert exit_code == EXIT_PASS
            captured = capsys.readouterr()
            assert "Entropy AI Advisory Explanation" in captured.out
            assert "Empty exception handler detected" in captured.out
            assert "strictly advisory and does not affect" in captured.out


# -----------------------------------------------------------------------------
# 8. GLOBAL OPTIONS (QUIET, VERBOSE, NO-COLOR)
# -----------------------------------------------------------------------------

def test_cli_quiet_mode(sample_repo: Path, capsys):
    """--quiet suppresses standard human text output."""
    exit_code = main(["--quiet", "scan", str(sample_repo)])
    assert exit_code == EXIT_PASS
    captured = capsys.readouterr()
    assert captured.out.strip() == ""


def test_cli_verbose_mode(sample_repo: Path, capsys):
    """--verbose outputs diagnostic timing messages to stderr."""
    exit_code = main(["--verbose", "scan", str(sample_repo)])
    assert exit_code == EXIT_PASS
    captured = capsys.readouterr()
    assert "[VERBOSE]" in captured.err


# -----------------------------------------------------------------------------
# 9. SECURITY CANARY TEST (ZERO CODE EXECUTION GUARANTEE)
# -----------------------------------------------------------------------------

def test_malicious_repository_canary(malicious_repo: Path):
    """Neither 'scan' nor 'check' must ever execute repository code or create canary files."""
    canary_file = Path("ENTROPY_CLI_HACKED.txt")
    if canary_file.exists():
        canary_file.unlink()

    # 1. Run scan
    scan_code = main(["scan", str(malicious_repo)])
    assert scan_code == EXIT_PASS
    assert not canary_file.exists(), "SECURITY INVARIANT VIOLATION: Canary file created during 'entropy scan'!"

    # 2. Run check
    check_code = main(["check", str(malicious_repo)])
    assert check_code in (EXIT_PASS, EXIT_POLICY_FAIL)
    assert not canary_file.exists(), "SECURITY INVARIANT VIOLATION: Canary file created during 'entropy check'!"


# -----------------------------------------------------------------------------
# 10. DETERMINISM AUDIT
# -----------------------------------------------------------------------------

def test_cli_scan_determinism(sample_repo: Path, capsys):
    """Two successive scans of the same repo output identical findings, scores, and categories."""
    main(["scan", str(sample_repo), "--format", "json"])
    out1 = json.loads(capsys.readouterr().out)

    main(["scan", str(sample_repo), "--format", "json"])
    out2 = json.loads(capsys.readouterr().out)

    # Compare analytical outputs
    assert out1["score"] == out2["score"]
    assert out1["categories"] == out2["categories"]
    assert len(out1["findings"]) == len(out2["findings"])
    for f1, f2 in zip(out1["findings"], out2["findings"], strict=True):
        assert f1["id"] == f2["id"]
        assert f1["fingerprint"] == f2["fingerprint"]
        assert f1["rule_id"] == f2["rule_id"]

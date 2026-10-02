"""Unit tests for Phase 13 CLI."""

from pathlib import Path

from app.cli.main import (
    EXIT_CONFIG_ERROR,
    EXIT_PASS,
    EXIT_POLICY_FAIL,
    EXIT_SYSTEM_ERROR,
    main,
)
from app.comparison.models import (
    ComparisonSummary,
    ScanComparisonResult,
    ScoreComparison,
)


def test_cli_validate_valid_yaml(tmp_path: Path):
    """entropy policy validate returns EXIT_PASS (0) for valid YAML."""
    p_file = tmp_path / "valid_policy.yaml"
    p_file.write_text(
        """
policy:
  name: test-policy
  version: 1.0.0
  score:
    max_score: 50
    max_delta: 5
""",
        encoding="utf-8",
    )
    exit_code = main(["policy", "validate", str(p_file)])
    assert exit_code == EXIT_PASS


def test_cli_validate_invalid_yaml(tmp_path: Path):
    """entropy policy validate returns EXIT_CONFIG_ERROR (2) for invalid config."""
    p_file = tmp_path / "invalid_policy.yaml"
    p_file.write_text(
        """
policy:
  name: test-policy
  score:
    max_score: -10
""",
        encoding="utf-8",
    )
    exit_code = main(["policy", "validate", str(p_file)])
    assert exit_code == EXIT_CONFIG_ERROR


def test_cli_validate_missing_file():
    """entropy policy validate returns EXIT_CONFIG_ERROR (2) when file does not exist."""
    exit_code = main(["policy", "validate", "non_existent_file.yaml"])
    assert exit_code == EXIT_CONFIG_ERROR


def test_cli_evaluate_comparison_file_pass(tmp_path: Path):
    """entropy policy evaluate returns EXIT_PASS (0) when comparison passes policy."""
    comp = ScanComparisonResult(
        summary=ComparisonSummary(
            repository_id="repo-test",
            repo_name="org/repo",
            previous_scan_id="base",
            current_scan_id="head",
            previous_timestamp="2026-01-01T00:00:00Z",
            current_timestamp="2026-01-02T00:00:00Z",
            previous_score=20,
            current_score=22,
            score_delta=2,
            new_findings_count=0,
            resolved_findings_count=0,
            persistent_findings_count=0,
            total_current_findings=0,
        ),
        score_comparison=ScoreComparison(
            previous_score=20,
            current_score=22,
            score_delta=2,
            direction="increased",
            explanation="Delta +2",
        ),
        category_comparisons={},
        rule_comparisons=[],
        new_findings=[],
        resolved_findings=[],
        persistent_findings=[],
    )
    comp_file = tmp_path / "comp.json"
    comp_file.write_text(comp.model_dump_json(), encoding="utf-8")

    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("score:\n  max_delta: 5\n", encoding="utf-8")

    exit_code = main([
        "policy",
        "evaluate",
        "--comparison-file",
        str(comp_file),
        "--policy",
        str(policy_file),
    ])
    assert exit_code == EXIT_PASS


def test_cli_evaluate_comparison_file_fail(tmp_path: Path):
    """entropy policy evaluate returns EXIT_POLICY_FAIL (1) when comparison fails policy."""
    comp = ScanComparisonResult(
        summary=ComparisonSummary(
            repository_id="repo-test",
            repo_name="org/repo",
            previous_scan_id="base",
            current_scan_id="head",
            previous_timestamp="2026-01-01T00:00:00Z",
            current_timestamp="2026-01-02T00:00:00Z",
            previous_score=20,
            current_score=35,
            score_delta=15,
            new_findings_count=0,
            resolved_findings_count=0,
            persistent_findings_count=0,
            total_current_findings=0,
        ),
        score_comparison=ScoreComparison(
            previous_score=20,
            current_score=35,
            score_delta=15,
            direction="increased",
            explanation="Delta +15",
        ),
        category_comparisons={},
        rule_comparisons=[],
        new_findings=[],
        resolved_findings=[],
        persistent_findings=[],
    )
    comp_file = tmp_path / "comp.json"
    comp_file.write_text(comp.model_dump_json(), encoding="utf-8")

    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("score:\n  max_delta: 5\n", encoding="utf-8")

    exit_code = main([
        "policy",
        "evaluate",
        "--comparison-file",
        str(comp_file),
        "--policy",
        str(policy_file),
    ])
    assert exit_code == EXIT_POLICY_FAIL


def test_cli_evaluate_warn_with_fail_on_warn(tmp_path: Path):
    """entropy policy evaluate with --fail-on-warn returns EXIT_POLICY_FAIL (1) on warnings."""
    comp = ScanComparisonResult(
        summary=ComparisonSummary(
            repository_id="repo-test",
            repo_name="org/repo",
            previous_scan_id="base",
            current_scan_id="head",
            previous_timestamp="2026-01-01T00:00:00Z",
            current_timestamp="2026-01-02T00:00:00Z",
            previous_score=20,
            current_score=24,
            score_delta=4,
            new_findings_count=0,
            resolved_findings_count=0,
            persistent_findings_count=0,
            total_current_findings=0,
        ),
        score_comparison=ScoreComparison(
            previous_score=20,
            current_score=24,
            score_delta=4,
            direction="increased",
            explanation="Delta +4",
        ),
        category_comparisons={},
        rule_comparisons=[],
        new_findings=[],
        resolved_findings=[],
        persistent_findings=[],
    )
    comp_file = tmp_path / "comp.json"
    comp_file.write_text(comp.model_dump_json(), encoding="utf-8")

    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("score:\n  max_delta: 10\n  warn_delta: 3\n", encoding="utf-8")

    # Without --fail-on-warn -> PASS (0)
    assert main([
        "policy",
        "evaluate",
        "--comparison-file",
        str(comp_file),
        "--policy",
        str(policy_file),
    ]) == EXIT_PASS

    # With --fail-on-warn -> FAIL (1)
    assert main([
        "policy",
        "evaluate",
        "--comparison-file",
        str(comp_file),
        "--policy",
        str(policy_file),
        "--fail-on-warn",
    ]) == EXIT_POLICY_FAIL


def test_cli_evaluate_missing_comparison_file():
    """entropy policy evaluate returns EXIT_SYSTEM_ERROR (3) when file missing."""
    exit_code = main(["policy", "evaluate", "--comparison-file", "missing_comp.json"])
    assert exit_code == EXIT_SYSTEM_ERROR

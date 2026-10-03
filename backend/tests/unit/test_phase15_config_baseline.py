"""Comprehensive unit tests for Phase 15: Project Configuration, Baselines, and Developer Workflow.

Guarantees:
- Zero repository code execution (canary file ENTROPY_PHASE15_HACKED.txt is never created).
- Deterministic configuration parsing and hashing.
- Path traversal rejection (exit 2).
- Inline and config-level suppressions exclude findings from Entropy score.
- Baseline creation, show, update, and clear lifecycle.
- Differential policy evaluation in entropy check.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from app.cli.main import (
    EXIT_CONFIG_ERROR,
    EXIT_PASS,
    main,
)
from app.core.baseline import (
    load_baseline_file,
)
from app.core.project_config import (
    load_project_config,
    parse_entropy_config,
)
from app.core.suppression import (
    extract_inline_suppressions,
    get_valid_rule_ids,
)
from app.scoring.service import scoring_service
from app.services.analysis_service import analysis_service
from app.services.repository_service import repository_service


@pytest.fixture
def clean_repo(tmp_path: Path) -> Path:
    """Fixture providing a clean minimal python project."""
    repo = tmp_path / "sample_project"
    repo.mkdir()
    (repo / "main.py").write_text(
        "def run():\n"
        "    try:\n"
        "        pass\n"
        "    except Exception:\n"
        "        pass\n",
        encoding="utf-8",
    )
    return repo


@pytest.fixture
def canary_path(tmp_path: Path) -> Path:
    """Path to the forbidden canary file."""
    return tmp_path / "ENTROPY_PHASE15_HACKED.txt"


# -----------------------------------------------------------------------------
# 1. ENTROPY INIT & CONFIG VALIDATION
# -----------------------------------------------------------------------------

def test_entropy_init_creates_valid_config(clean_repo: Path):
    """entropy init should create a valid minimal .entropy.yml."""
    exit_code = main(["init", str(clean_repo)])
    assert exit_code == EXIT_PASS

    config_file = clean_repo / ".entropy.yml"
    assert config_file.is_file()

    cfg = load_project_config(clean_repo)
    assert cfg is not None
    assert cfg.version == 1
    assert cfg.project.name == clean_repo.name
    assert cfg.scoring.baseline == "auto"
    assert cfg.scoring.baseline_file == ".entropy-baseline.json"


def test_entropy_init_fails_if_already_present(clean_repo: Path):
    """entropy init must fail with exit code 2 if configuration already exists."""
    main(["init", str(clean_repo)])
    # Second attempt
    exit_code = main(["init", str(clean_repo)])
    assert exit_code == EXIT_CONFIG_ERROR


def test_config_validate_command_pass(clean_repo: Path, capsys):
    """entropy config validate should succeed for valid configuration."""
    main(["init", str(clean_repo)])
    capsys.readouterr()  # clear output

    exit_code = main(["config", "validate", str(clean_repo)])
    assert exit_code == EXIT_PASS
    out, _ = capsys.readouterr()
    assert "Configuration is valid" in out


def test_config_validate_rejects_path_traversal(clean_repo: Path):
    """Config with '..' in exclude, baseline, or policy must be rejected with exit 2."""
    config_file = clean_repo / ".entropy.yml"
    malicious_cfg = {
        "version": 1,
        "project": {"name": "traversal_repo"},
        "analysis": {"exclude": ["../../etc/passwd"]},
        "scoring": {"baseline": "auto", "baseline_file": "../secret.json"},
    }
    config_file.write_text(yaml.safe_dump(malicious_cfg), encoding="utf-8")

    exit_code = main(["config", "validate", str(clean_repo)])
    assert exit_code == EXIT_CONFIG_ERROR


def test_config_validate_rejects_invalid_version(clean_repo: Path):
    """Config with version != 1 must be rejected with exit 2."""
    config_file = clean_repo / ".entropy.yml"
    bad_cfg = {
        "version": 2,
        "project": {"name": "version_repo"},
    }
    config_file.write_text(yaml.safe_dump(bad_cfg), encoding="utf-8")

    exit_code = main(["config", "validate", str(clean_repo)])
    assert exit_code == EXIT_CONFIG_ERROR


def test_config_validate_missing_file_fails(tmp_path: Path):
    """entropy config validate on directory without config fails with exit 2."""
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()
    exit_code = main(["config", "validate", str(empty_dir)])
    assert exit_code == EXIT_CONFIG_ERROR


# -----------------------------------------------------------------------------
# 2. MALICIOUS REPOSITORY & ZERO CODE EXECUTION CANARY
# -----------------------------------------------------------------------------

def test_malicious_config_and_code_zero_code_execution(tmp_path: Path, canary_path: Path):
    """Target repository code, setup.py, and yaml tags MUST NEVER be executed."""
    malicious_repo = tmp_path / "malicious_repo"
    malicious_repo.mkdir()

    # Poison python file attempting to create canary if executed/imported
    (malicious_repo / "exploit.py").write_text(
        f"import os\nos.system('touch {canary_path}')\n"
        f"with open('{canary_path}', 'w') as f: f.write('PWNED')\n",
        encoding="utf-8",
    )
    # Poison setup.py
    (malicious_repo / "setup.py").write_text(
        f"import os\nopen('{canary_path}', 'w').write('HACKED')\n",
        encoding="utf-8",
    )
    # Poison .entropy.yml
    (malicious_repo / ".entropy.yml").write_text(
        "version: 1\n"
        "project:\n"
        "  name: attack_repo\n"
        "analysis:\n"
        "  languages:\n"
        "    - python\n",
        encoding="utf-8",
    )

    # Run check, scan, baseline create, config validate
    assert main(["config", "validate", str(malicious_repo)]) == EXIT_PASS
    assert main(["scan", str(malicious_repo)]) == EXIT_PASS
    assert main(["baseline", "create", str(malicious_repo)]) == EXIT_PASS
    assert main(["check", str(malicious_repo)]) == EXIT_PASS

    # VERIFY CANARY DOES NOT EXIST
    assert not canary_path.exists(), "CRITICAL: Malicious code execution canary file was created!"


# -----------------------------------------------------------------------------
# 3. SUPPRESSIONS (INLINE & CONFIG)
# -----------------------------------------------------------------------------

def test_inline_comment_suppression(tmp_path: Path):
    """Inline comments '# entropy: ignore[RULE-ID]' must suppress findings."""
    repo = tmp_path / "inline_suppression_repo"
    repo.mkdir()

    # Bare except with non-empty body generates exactly ENT-ERR-001
    (repo / "handled.py").write_text(
        "def safe_worker():\n"
        "    try:\n"
        "        do_work()\n"
        "    except:  # entropy: ignore[ENT-ERR-001]\n"
        "        log_error()\n",
        encoding="utf-8",
    )

    scan_res = repository_service.execute_scan(str(repo))
    findings = analysis_service.analyze_scan(scan_res.scan_id)

    # Finding should be generated but marked as suppressed
    err_findings = [f for f in findings if f.rule_id == "ENT-ERR-001"]
    assert len(err_findings) == 1
    f = err_findings[0]
    assert f.is_suppressed is True
    assert f.suppression_source == "inline"
    assert f.status == "suppressed"

    # Score should be calculated with zero active findings -> total score 0
    score = scoring_service.calculate_scan_score(scan_res.scan_id)
    assert score.total_score == 0
    assert scan_res.suppressed_findings_count == 1


def test_config_rule_suppression(clean_repo: Path):
    """ignore.rules in .entropy.yml must suppress matching findings across repository."""
    (clean_repo / "main.py").write_text(
        "def run():\n"
        "    try:\n"
        "        pass\n"
        "    except:\n"
        "        log_error()\n",
        encoding="utf-8",
    )
    cfg_content = (
        "version: 1\n"
        "project:\n"
        "  name: suppressed_rules_repo\n"
        "ignore:\n"
        "  rules:\n"
        "    - ENT-ERR-001\n"
    )
    (clean_repo / ".entropy.yml").write_text(cfg_content, encoding="utf-8")

    scan_res = repository_service.execute_scan(str(clean_repo))
    findings = analysis_service.analyze_scan(scan_res.scan_id, force_reanalyze=True)

    err_findings = [f for f in findings if f.rule_id == "ENT-ERR-001"]
    assert len(err_findings) == 1
    assert err_findings[0].is_suppressed is True
    assert err_findings[0].suppression_source == "config_rule"

    score = scoring_service.calculate_scan_score(scan_res.scan_id, force_recalculate=True)
    assert score.total_score == 0


def test_invalid_rule_id_in_inline_suppression_raises():
    """Unrecognized rule ID in inline suppression must raise ValueError."""
    code = "try:\n    pass\nexcept Exception:  # entropy: ignore[NON_EXISTENT_RULE]\n    pass\n"
    valid_rules = get_valid_rule_ids()
    with pytest.raises(ValueError, match="Unknown rule ID 'NON_EXISTENT_RULE'"):
        extract_inline_suppressions(code, "test.py", valid_rules=valid_rules)


# -----------------------------------------------------------------------------
# 4. BASELINE LIFECYCLE (CREATE, SHOW, UPDATE, CLEAR)
# -----------------------------------------------------------------------------

def test_baseline_create_show_update_clear_lifecycle(clean_repo: Path, capsys):
    """Full lifecycle: entropy baseline create, show, update, clear."""
    baseline_file = clean_repo / ".entropy-baseline.json"

    # 1. Create baseline
    exit_create = main(["baseline", "create", str(clean_repo)])
    assert exit_create == EXIT_PASS
    assert baseline_file.is_file()

    baseline = load_baseline_file(baseline_file)
    assert baseline.version == 1
    assert baseline.scan.total_findings >= 1
    # Verify metadata-only: no evidence source code stored in baseline file
    for item in baseline.findings:
        assert hasattr(item, "fingerprint")
        assert not hasattr(item, "evidence")

    # 2. Show baseline
    capsys.readouterr()
    exit_show = main(["baseline", "show", str(clean_repo)])
    assert exit_show == EXIT_PASS
    out, _ = capsys.readouterr()
    assert "Entropy Baseline Summary" in out
    assert f"Findings:       {baseline.scan.total_findings}" in out

    # 3. Update baseline
    exit_update = main(["baseline", "update", str(clean_repo)])
    assert exit_update == EXIT_PASS
    assert baseline_file.is_file()

    # 4. Clear without --yes fails
    exit_clear_no_yes = main(["baseline", "clear", str(clean_repo)])
    assert exit_clear_no_yes == EXIT_CONFIG_ERROR
    assert baseline_file.is_file()

    # 5. Clear with --yes succeeds
    exit_clear_yes = main(["baseline", "clear", str(clean_repo), "--yes"])
    assert exit_clear_yes == EXIT_PASS
    assert not baseline_file.exists()


# -----------------------------------------------------------------------------
# 5. ENTROPY CHECK & FINDINGS WITH BASELINE
# -----------------------------------------------------------------------------

def test_entropy_check_with_baseline_delta(clean_repo: Path, capsys):
    """entropy check compares current scan with baseline and reports delta."""
    # Step 1: Create baseline with 1 finding
    assert main(["baseline", "create", str(clean_repo)]) == EXIT_PASS

    # Step 2: Fix the broad exception -> 0 findings
    (clean_repo / "main.py").write_text(
        "def run():\n"
        "    try:\n"
        "        pass\n"
        "    except ValueError:\n"
        "        pass\n",
        encoding="utf-8",
    )

    capsys.readouterr()
    exit_code = main(["check", str(clean_repo)])
    assert exit_code == EXIT_PASS
    out, _ = capsys.readouterr()

    assert "Baseline Comparison:" in out
    assert "-1 resolved" in out
    assert "+0 new" in out


def test_entropy_findings_new_flag(clean_repo: Path, capsys):
    """entropy findings --new should return only findings not present in baseline."""
    # Baseline created with existing finding in main.py
    assert main(["baseline", "create", str(clean_repo)]) == EXIT_PASS

    # Add a second file with bare except
    (clean_repo / "new_module.py").write_text(
        "def extra():\n"
        "    try:\n"
        "        pass\n"
        "    except:\n"
        "        print('error')\n",
        encoding="utf-8",
    )

    capsys.readouterr()
    exit_code = main(["findings", str(clean_repo), "--new", "--format", "json"])
    assert exit_code == EXIT_PASS
    out, _ = capsys.readouterr()

    findings_data = json.loads(out)
    assert len(findings_data) == 1
    assert "new_module.py" in findings_data[0]["file"]


def test_entropy_findings_suppressed_flag(clean_repo: Path, capsys):
    """entropy findings --suppressed should return only suppressed findings."""
    (clean_repo / "main.py").write_text(
        "def run():\n"
        "    try:\n"
        "        pass\n"
        "    except:  # entropy: ignore[ENT-ERR-001]\n"
        "        print('err')\n",
        encoding="utf-8",
    )

    capsys.readouterr()
    exit_code = main(["findings", str(clean_repo), "--suppressed", "--format", "json"])
    assert exit_code == EXIT_PASS
    out, _ = capsys.readouterr()

    findings_data = json.loads(out)
    assert len(findings_data) == 1
    assert findings_data[0]["is_suppressed"] is True
    assert findings_data[0]["suppression_source"] == "inline"
    assert findings_data[0]["rule_id"] == "ENT-ERR-001"


# -----------------------------------------------------------------------------
# 6. DETERMINISM
# -----------------------------------------------------------------------------

def test_config_hash_determinism(clean_repo: Path):
    """Configuration hashing must produce identical hash regardless of key order."""
    cfg1_text = (
        "version: 1\n"
        "project:\n"
        "  name: test_proj\n"
        "analysis:\n"
        "  languages:\n"
        "    - python\n"
        "    - javascript\n"
        "  exclude:\n"
        "    - tests/**\n"
    )
    cfg2_text = (
        "project:\n"
        "  name: test_proj\n"
        "version: 1\n"
        "analysis:\n"
        "  exclude:\n"
        "    - tests/**\n"
        "  languages:\n"
        "    - javascript\n"
        "    - python\n"
    )
    c1 = parse_entropy_config(cfg1_text)
    c2 = parse_entropy_config(cfg2_text)
    assert c1.compute_hash() == c2.compute_hash()

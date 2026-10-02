"""Phase 10 — Scan History, Comparison & Trend Intelligence Tests.

Tests all required acceptance criteria:
1. Scan persistence to database and snapshot integrity.
2. Multiple scans of same repository distinguishable by scan_id and timestamp.
3. Scans from different repositories isolated by repository_id.
4. History pagination, filtering, and newest-first ordering.
5. Trend empty state (0 scans) and single-scan state (1 scan).
6. Trend chronological score and category progression (2+ scans).
7. Comparison: 0 -> 0 findings.
8. Comparison: identical findings (0 new, 0 resolved, all persistent).
9. Comparison: finding lifecycle (new, resolved, persistent).
10. Comparison: score deltas and neutral directional descriptions.
11. Comparison: category deltas preserving NOT_ANALYZED explicitly.
12. Comparison: dynamic rule-level count deltas.
13. Determinism: repeated comparison produces 100% identical output.
14. Real truth-test repository: Scan A (debt) -> Scan B (fixed) -> Scan C (new debt).
15. Malicious canary: zero-code execution invariant preserved.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.models.domain.enums import DebtCategory
from app.models.domain.scan import RepositoryMetadata, RepositoryScanResult
from app.persistence.database import scan_db
from app.scoring.models import CategoryScoreBreakdown, DebtScoreResult, DebtScoreTier

client = TestClient(app)


def _scan_repo_api(repo_path: Path, repo_name: str = "TestRepo"):
    """Helper to scan repository via API and return scan_id, findings, and score."""
    resp = client.post(
        "/api/v1/repositories/scan", json={"path": str(repo_path), "repo_name": repo_name}
    )
    assert resp.status_code == 201, f"Scan failed: {resp.text}"
    scan_id = resp.json()["scan_id"]
    findings = client.get(f"/api/v1/scans/{scan_id}/findings").json()
    score = client.get(f"/api/v1/scans/{scan_id}/score").json()
    return scan_id, findings, score


# ==============================================================================
# 1. Scan Persistence to Database
# ==============================================================================


def test_1_scan_persisted_to_database(tmp_path: Path):
    """Scans and scores are persisted to SQLite database and snapshot can be retrieved."""
    repo = tmp_path / "persist_repo"
    repo.mkdir()
    (repo / "clean.py").write_text("def hello(): return 'world'\n")

    scan_id, findings, score = _scan_repo_api(repo, "Persist_Repo")

    # Verify persisted in database
    db_scan = scan_db.get_scan(scan_id)
    assert db_scan is not None
    assert db_scan.scan_id == scan_id
    assert db_scan.repository.name == "Persist_Repo"
    assert db_scan.score is not None
    assert db_scan.score.total_score == score["total_score"]

    # Verify snapshot
    snapshot = scan_db.get_snapshot(scan_id)
    assert snapshot is not None
    assert snapshot.scan_id == scan_id
    assert snapshot.entropy_score == score["total_score"]
    assert snapshot.total_loc > 0


# ==============================================================================
# 2. Multiple Scans of Same Repository
# ==============================================================================


def test_2_multiple_scans_same_repository(tmp_path: Path):
    """Multiple scans of the same repository share the same repository_id and have distinct scan_ids."""
    repo = tmp_path / "multi_repo"
    repo.mkdir()
    (repo / "app.py").write_text("def run(): pass\n")

    scan_id_1, _, _ = _scan_repo_api(repo, "Multi_Repo")
    scan_id_2, _, _ = _scan_repo_api(repo, "Multi_Repo")

    assert scan_id_1 != scan_id_2

    scan1 = scan_db.get_scan(scan_id_1)
    scan2 = scan_db.get_scan(scan_id_2)

    assert scan1 is not None and scan2 is not None
    assert scan1.repository.repository_id == scan2.repository.repository_id


# ==============================================================================
# 3. Scans from Different Repositories Are Isolated
# ==============================================================================


def test_3_scans_from_different_repositories_isolated(tmp_path: Path):
    """Scans from different repositories have distinct repository_ids and isolated histories."""
    repo_a = tmp_path / "repo_a"
    repo_a.mkdir()
    (repo_a / "a.py").write_text("x = 1\n")

    repo_b = tmp_path / "repo_b"
    repo_b.mkdir()
    (repo_b / "b.py").write_text("y = 2\n")

    scan_id_a, _, _ = _scan_repo_api(repo_a, "Repo_A")
    scan_id_b, _, _ = _scan_repo_api(repo_b, "Repo_B")

    scan_a = scan_db.get_scan(scan_id_a)
    scan_b = scan_db.get_scan(scan_id_b)

    assert scan_a.repository.repository_id != scan_b.repository.repository_id

    # List history for Repo A
    resp_a = client.get(f"/api/v1/repositories/{scan_a.repository.repository_id}/scans").json()
    assert any(s["scan_id"] == scan_id_a for s in resp_a["items"])
    assert not any(s["scan_id"] == scan_id_b for s in resp_a["items"])


# ==============================================================================
# 4. History Ordering & Pagination
# ==============================================================================


def test_4_history_ordering_and_pagination(tmp_path: Path):
    """Scan history is returned newest-first with accurate pagination metadata."""
    repo = tmp_path / "history_repo"
    repo.mkdir()
    (repo / "f.py").write_text("def f(): pass\n")

    scan_ids = []
    for _ in range(3):
        sid, _, _ = _scan_repo_api(repo, "History_Repo")
        scan_ids.append(sid)

    scan_obj = scan_db.get_scan(scan_ids[0])
    repo_id = scan_obj.repository.repository_id

    # Page 1, size 2
    resp = client.get(f"/api/v1/repositories/{repo_id}/scans?page=1&page_size=2").json()
    assert resp["total"] >= 3
    assert len(resp["items"]) == 2
    assert resp["page"] == 1
    assert resp["page_size"] == 2
    assert resp["total_pages"] >= 2
    # Newest scan is first item
    assert resp["items"][0]["scan_id"] == scan_ids[2]

    # Page 2, size 2
    resp_p2 = client.get(f"/api/v1/repositories/{repo_id}/scans?page=2&page_size=2").json()
    assert len(resp_p2["items"]) >= 1


# ==============================================================================
# 5. Trend Empty State & Single Scan State
# ==============================================================================


def test_5_trend_empty_and_one_scan_states(tmp_path: Path):
    """Trend endpoint handles 0 scans and 1 scan with appropriate neutral messages."""
    # 0 scans
    resp_empty = client.get("/api/v1/repositories/non_existent_repo_id/trend").json()
    assert resp_empty["total_scans"] == 0
    assert len(resp_empty["points"]) == 0
    assert resp_empty["message"] == "No scan history available"

    # 1 scan
    repo = tmp_path / "single_scan_repo"
    repo.mkdir()
    (repo / "main.py").write_text("print('hello')\n")
    scan_id, _, _ = _scan_repo_api(repo, "Single_Scan_Repo")

    scan_obj = scan_db.get_scan(scan_id)
    repo_id = scan_obj.repository.repository_id

    resp_one = client.get(f"/api/v1/repositories/{repo_id}/trend").json()
    assert resp_one["total_scans"] == 1
    assert len(resp_one["points"]) == 1
    assert resp_one["message"] == "Not enough historical data for a trend"


# ==============================================================================
# 6. Trend Progression for Multiple Scans
# ==============================================================================


def test_6_trend_progression_multiple_scans(tmp_path: Path):
    """Trend endpoint returns chronological score progression for 2+ scans."""
    repo = tmp_path / "trend_repo"
    repo.mkdir()
    (repo / "code.py").write_text("def a(): pass\n")

    sid1, _, _ = _scan_repo_api(repo, "Trend_Repo")
    sid2, _, _ = _scan_repo_api(repo, "Trend_Repo")

    repo_id = scan_db.get_scan(sid1).repository.repository_id

    trend = client.get(f"/api/v1/repositories/{repo_id}/trend").json()
    assert trend["total_scans"] >= 2
    assert len(trend["points"]) >= 2
    assert trend["message"] is None
    # Chronological ordering (oldest first)
    assert trend["points"][0]["scan_id"] == sid1
    assert trend["points"][1]["scan_id"] == sid2


# ==============================================================================
# 7. Comparison: Zero to Zero Findings
# ==============================================================================


def test_7_comparison_zero_to_zero_findings(tmp_path: Path):
    """Comparing two clean scans produces 0 deltas and 0 finding movements."""
    repo = tmp_path / "clean_comparison_repo"
    repo.mkdir()
    (repo / "clean.py").write_text("def clean_function(): return 42\n")

    sid1, _, _ = _scan_repo_api(repo, "Clean_Comp")
    sid2, _, _ = _scan_repo_api(repo, "Clean_Comp")

    comp = client.get(f"/api/v1/scans/{sid2}/compare/{sid1}").json()
    assert comp["summary"]["score_delta"] == 0
    assert comp["summary"]["new_findings_count"] == 0
    assert comp["summary"]["resolved_findings_count"] == 0
    assert comp["summary"]["persistent_findings_count"] == 0
    assert comp["score_comparison"]["direction"] == "unchanged"


# ==============================================================================
# 8. Comparison: Identical Findings (Persistent)
# ==============================================================================


def test_8_comparison_identical_findings_persistent(tmp_path: Path):
    """Scanning identical debt twice results in all persistent findings, 0 new, 0 resolved."""
    repo = tmp_path / "persistent_debt_repo"
    repo.mkdir()
    # Code with intentional broad exception handler
    (repo / "bad.py").write_text(
        "def query():\n    try:\n        pass\n    except Exception:\n        pass\n"
    )

    sid1, _, _ = _scan_repo_api(repo, "Persistent_Repo")
    sid2, _, _ = _scan_repo_api(repo, "Persistent_Repo")

    comp = client.get(f"/api/v1/scans/{sid2}/compare/{sid1}").json()
    assert comp["summary"]["score_delta"] == 0
    assert comp["summary"]["new_findings_count"] == 0
    assert comp["summary"]["resolved_findings_count"] == 0
    assert comp["summary"]["persistent_findings_count"] >= 1
    assert comp["score_comparison"]["direction"] == "unchanged"


# ==============================================================================
# 9. Comparison: Finding Lifecycle (New, Resolved, Persistent)
# ==============================================================================


def test_9_comparison_finding_lifecycle_new_and_resolved(tmp_path: Path):
    """Comparison accurately classifies new, resolved, and persistent findings."""
    repo = tmp_path / "lifecycle_repo"
    repo.mkdir()

    # Step 1: File A has broad exception, File B has bare except
    (repo / "a.py").write_text(
        "def fa():\n    try:\n        pass\n    except Exception:\n        pass\n"
    )
    (repo / "b.py").write_text("def fb():\n    try:\n        pass\n    except:\n        pass\n")
    sid1, findings1, _ = _scan_repo_api(repo, "Lifecycle_Repo")

    # Step 2: Fix File A (removes exception finding), keep File B, add File C with hardcoded password
    (repo / "a.py").write_text("def fa():\n    return 'clean'\n")
    (repo / "c.py").write_text("API_SECRET_KEY = 'super_secret_password_12345'\n")
    sid2, findings2, _ = _scan_repo_api(repo, "Lifecycle_Repo")

    comp = client.get(f"/api/v1/scans/{sid2}/compare/{sid1}").json()

    # File A finding resolved
    assert comp["summary"]["resolved_findings_count"] >= 1
    assert any("a.py" in f["file"] for f in comp["resolved_findings"])
    resolved_item = next(f for f in comp["resolved_findings"] if "a.py" in f["file"])
    assert resolved_item["resolution_status"] == "No longer detected since previous scan"

    # File C finding new
    assert comp["summary"]["new_findings_count"] >= 1
    assert any("c.py" in f["file"] for f in comp["new_findings"])

    # File B finding persistent
    assert comp["summary"]["persistent_findings_count"] >= 1
    assert any("b.py" in f["file"] for f in comp["persistent_findings"])


# ==============================================================================
# 10. Comparison: Score Deltas & Direction
# ==============================================================================


def test_10_comparison_score_deltas_direction(tmp_path: Path):
    """Score delta reflects worsening or improvement with neutral terminology."""
    repo = tmp_path / "delta_repo"
    repo.mkdir()

    # Step 1: Clean code
    (repo / "app.py").write_text("def run(): return 1\n")
    sid1, _, _ = _scan_repo_api(repo, "Delta_Repo")

    # Step 2: Add multiple debt items (increases debt score)
    (repo / "app.py").write_text(
        "import os\ndef run():\n    try:\n        pass\n    except Exception:\n        pass\n"
    )
    (repo / "leak.py").write_text(
        "SECRET_KEY = 'UnsafeHardcodedProductionSecretKeyString987654321'\n"
    )
    sid2, _, _ = _scan_repo_api(repo, "Delta_Repo")

    # Compare 1 -> 2 (debt increased)
    comp_worse = client.get(f"/api/v1/scans/{sid2}/compare/{sid1}").json()
    assert comp_worse["summary"]["score_delta"] > 0
    assert comp_worse["score_comparison"]["direction"] == "increased"
    assert "increased" in comp_worse["score_comparison"]["explanation"].lower()

    # Compare 2 -> 1 (debt decreased)
    comp_improved = client.get(f"/api/v1/scans/{sid1}/compare/{sid2}").json()
    assert comp_improved["summary"]["score_delta"] < 0
    assert comp_improved["score_comparison"]["direction"] == "decreased"
    assert "decreased" in comp_improved["score_comparison"]["explanation"].lower()


# ==============================================================================
# 11. Category Comparison Preserves NOT_ANALYZED
# ==============================================================================


def test_11_category_comparison_preserves_not_analyzed():
    """If a category was not_analyzed in one scan, score_delta is None and not converted to 0."""
    from app.comparison.service import comparison_service

    # Construct synthetic scan results testing NOT_ANALYZED invariant
    cat_analyzed = CategoryScoreBreakdown(
        category=DebtCategory.ERROR_HANDLING,
        status="analyzed",
        score=20.0,
        finding_count=4,
        weight=1.0,
        explanation="Analyzed error handling debt",
    )
    cat_not_analyzed = CategoryScoreBreakdown(
        category=DebtCategory.ERROR_HANDLING,
        status="not_analyzed",
        score=None,
        finding_count=0,
        weight=1.0,
        explanation="Not yet analyzed",
    )

    score_analyzed = DebtScoreResult(
        total_score=20,
        tier=DebtScoreTier.LOW,
        category_scores={DebtCategory.ERROR_HANDLING: cat_analyzed},
        analyzed_categories=[DebtCategory.ERROR_HANDLING],
        total_findings=4,
        total_loc=100,
        analyzed_files=1,
        formula_summary="Deterministic test formula",
    )
    score_not_analyzed = DebtScoreResult(
        total_score=0,
        tier=DebtScoreTier.VERY_LOW,
        category_scores={DebtCategory.ERROR_HANDLING: cat_not_analyzed},
        analyzed_categories=[],
        total_findings=0,
        total_loc=100,
        analyzed_files=1,
        formula_summary="Deterministic test formula",
    )

    repo_meta = RepositoryMetadata(name="Synthetic", path="/tmp/synth")

    scan_prev = RepositoryScanResult(
        scan_id="prev_id",
        repository=repo_meta,
        status="completed",
        score=score_not_analyzed,
        started_at="2026-01-01T00:00:00Z",
    )
    scan_curr = RepositoryScanResult(
        scan_id="curr_id",
        repository=repo_meta,
        status="completed",
        score=score_analyzed,
        started_at="2026-01-02T00:00:00Z",
    )

    res = comparison_service.compare_scans(current_scan=scan_curr, previous_scan=scan_prev)
    cat_comp = res.category_comparisons["error_handling"]

    # Invariant: Delta MUST be None because previous scan was not analyzed!
    assert cat_comp.previous_status == "not_analyzed"
    assert cat_comp.current_status == "analyzed"
    assert cat_comp.score_delta is None
    assert cat_comp.previous_score is None


# ==============================================================================
# 12. Dynamic Rule-Level Deltas
# ==============================================================================


def test_12_rule_level_deltas(tmp_path: Path):
    """Dynamic rule-level count differences are computed and sorted by absolute delta."""
    repo = tmp_path / "rule_delta_repo"
    repo.mkdir()

    (repo / "err.py").write_text(
        "def f1():\n"
        "    try: pass\n"
        "    except Exception: pass\n"
        "def f2():\n"
        "    try: pass\n"
        "    except Exception: pass\n"
    )
    sid1, _, _ = _scan_repo_api(repo, "Rule_Repo")

    (repo / "err.py").write_text("def f1():\n    try: pass\n    except Exception: pass\n")
    sid2, _, _ = _scan_repo_api(repo, "Rule_Repo")

    comp = client.get(f"/api/v1/scans/{sid2}/compare/{sid1}").json()
    rule_deltas = comp["rule_comparisons"]
    assert len(rule_deltas) >= 1

    err_rule = next((r for r in rule_deltas if r["rule_id"] == "ENT-ERR-002"), None)
    assert err_rule is not None
    assert err_rule["previous_count"] == 2
    assert err_rule["current_count"] == 1
    assert err_rule["delta"] == -1


# ==============================================================================
# 13. Comparison Determinism
# ==============================================================================


def test_13_comparison_determinism(tmp_path: Path):
    """Running the exact same scan comparison twice produces 100% identical JSON outputs."""
    repo = tmp_path / "det_comp_repo"
    repo.mkdir()
    (repo / "m.py").write_text("def run():\n    try: pass\n    except Exception: pass\n")

    sid1, _, _ = _scan_repo_api(repo, "Det_Repo")
    sid2, _, _ = _scan_repo_api(repo, "Det_Repo")

    comp_1 = client.get(f"/api/v1/scans/{sid2}/compare/{sid1}").json()
    comp_2 = client.get(f"/api/v1/scans/{sid2}/compare/{sid1}").json()

    assert comp_1 == comp_2


# ==============================================================================
# 14. Real Truth-Test Repository (A -> B -> C Lifecycle)
# ==============================================================================


def test_14_real_truth_test_lifecycle(tmp_path: Path):
    """Real lifecycle verification: Scan A (with debt) -> Scan B (resolved) -> Scan C (new debt)."""
    repo = tmp_path / "phase10_truth_test"
    repo.mkdir()

    # Step A: bad.py contains broad exception handler
    (repo / "bad.py").write_text(
        "def compute(data):\n"
        "    try:\n"
        "        return data['val']\n"
        "    except Exception:\n"
        "        pass\n"
    )
    sid_a, findings_a, score_a = _scan_repo_api(repo, "Truth_Repo")
    assert len(findings_a) >= 1
    finding_a_fp = findings_a[0]["fingerprint"]

    # Step B: Developer fixes the broad exception handler
    (repo / "bad.py").write_text("def compute(data):\n    return data.get('val')\n")
    sid_b, findings_b, score_b = _scan_repo_api(repo, "Truth_Repo")
    assert len(findings_b) == 0

    # Compare A -> B: finding_a is resolved, score decreased
    comp_ab = client.get(f"/api/v1/scans/{sid_b}/compare/{sid_a}").json()
    assert comp_ab["summary"]["resolved_findings_count"] >= 1
    assert comp_ab["summary"]["new_findings_count"] == 0
    assert comp_ab["score_comparison"]["direction"] == "decreased"
    assert any(f["fingerprint"] == finding_a_fp for f in comp_ab["resolved_findings"])

    # Step C: Add a new debt pattern (hardcoded API key)
    (repo / "bad.py").write_text(
        "def compute(data):\n"
        "    return data.get('val')\n\n"
        "SECRET_KEY = 'UnsafeHardcodedProductionSecretKeyString987654321'\n"
    )
    sid_c, findings_c, score_c = _scan_repo_api(repo, "Truth_Repo")
    assert len(findings_c) >= 1

    # Compare B -> C: new finding detected, resolved = 0
    comp_bc = client.get(f"/api/v1/scans/{sid_c}/compare/{sid_b}").json()
    assert comp_bc["summary"]["new_findings_count"] >= 1
    assert comp_bc["summary"]["resolved_findings_count"] == 0
    assert comp_bc["score_comparison"]["direction"] == "increased"

    # Compare A -> C: 1 resolved (from A), 1 new (from C)
    comp_ac = client.get(f"/api/v1/scans/{sid_c}/compare/{sid_a}").json()
    assert comp_ac["summary"]["resolved_findings_count"] >= 1
    assert comp_ac["summary"]["new_findings_count"] >= 1


# ==============================================================================
# 15. Malicious Canary Zero Code Execution Invariant
# ==============================================================================


def test_15_malicious_canary_zero_code_execution(tmp_path: Path):
    """Malicious canary is never executed during scan, history lookup, or comparison."""
    repo = tmp_path / "malicious_phase10_repo"
    repo.mkdir()

    canary = tmp_path / "ENTROPY_WAS_HACKED.txt"
    if canary.exists():
        canary.unlink()

    malicious_code = (
        "from pathlib import Path\n\n"
        f"Path({str(canary)!r}).write_text('EXECUTED')\n\n"
        "def harmless(): return True\n"
    )
    (repo / "exploit.py").write_text(malicious_code)

    sid1, _, _ = _scan_repo_api(repo, "Malicious_Repo")
    sid2, _, _ = _scan_repo_api(repo, "Malicious_Repo")

    # Run history & comparison
    client.get(f"/api/v1/scans/{sid2}/compare/{sid1}")

    # Security Invariant: Canary must never be executed!
    assert not canary.exists(), (
        "SECURITY INVARIANT VIOLATED: Malicious repository code was executed!"
    )

"""Phase 10 Validation Script: Verifies real Entropy repository scan history, comparison, and trend intelligence."""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.persistence.database import scan_db

client = TestClient(app)


def run_phase10_verification():
    entropy_repo_path = str(Path(__file__).resolve().parents[2])

    print("=" * 70)
    print("PHASE 10 — SCAN HISTORY, SCAN COMPARISON & TREND INTELLIGENCE AUDIT")
    print("=" * 70)
    print(f"\nTarget Real Repository: {entropy_repo_path}")

    # --- Step 1: Scan 1 ---
    print("\n[Step 1] Executing Scan 1 on real Entropy repository...")
    resp1 = client.post(
        "/api/v1/repositories/scan",
        json={"path": entropy_repo_path, "repo_name": "Entropy_Real_Repo"},
    )
    assert resp1.status_code == 201, f"Scan 1 failed: {resp1.text}"
    scan1_data = resp1.json()
    sid1 = scan1_data["scan_id"]
    findings1 = client.get(f"/api/v1/scans/{sid1}/findings").json()
    score1 = client.get(f"/api/v1/scans/{sid1}/score").json()
    print(f"  ✓ Scan 1 completed: {sid1[:8]}")
    print(
        f"    Score: {score1['total_score']}/100 ({score1['tier']}) | Total Findings: {len(findings1)}"
    )

    # --- Step 2: Scan 2 ---
    print("\n[Step 2] Executing Scan 2 on real Entropy repository...")
    resp2 = client.post(
        "/api/v1/repositories/scan",
        json={"path": entropy_repo_path, "repo_name": "Entropy_Real_Repo"},
    )
    assert resp2.status_code == 201, f"Scan 2 failed: {resp2.text}"
    scan2_data = resp2.json()
    sid2 = scan2_data["scan_id"]
    findings2 = client.get(f"/api/v1/scans/{sid2}/findings").json()
    score2 = client.get(f"/api/v1/scans/{sid2}/score").json()
    print(f"  ✓ Scan 2 completed: {sid2[:8]}")
    print(
        f"    Score: {score2['total_score']}/100 ({score2['tier']}) | Total Findings: {len(findings2)}"
    )

    # Distinct scan IDs
    assert sid1 != sid2, "Scan IDs must be distinct"

    # --- Step 3: Database Persistence Verification ---
    print("\n[Step 3] Verifying SQLite Database Persistence...")
    snap1 = scan_db.get_snapshot(sid1)
    snap2 = scan_db.get_snapshot(sid2)
    assert snap1 is not None, "Scan 1 snapshot not persisted"
    assert snap2 is not None, "Scan 2 snapshot not persisted"
    repo_id = snap1.repository_id
    assert snap2.repository_id == repo_id, "Repository ID must be deterministic"
    print(f"  ✓ Repository ID derived: {repo_id}")
    print(
        f"  ✓ Scan 1 persisted: entropy_score={snap1.entropy_score}, findings={snap1.finding_count}, LOC={snap1.total_loc}"
    )
    print(
        f"  ✓ Scan 2 persisted: entropy_score={snap2.entropy_score}, findings={snap2.finding_count}, LOC={snap2.total_loc}"
    )

    # --- Step 4: Repository History API ---
    print("\n[Step 4] Querying Repository Scan History API...")
    hist_resp = client.get(f"/api/v1/repositories/{repo_id}/scans?page=1&page_size=10").json()
    assert hist_resp["total"] >= 2, "Expected at least 2 historical scans"
    print(
        f"  ✓ Historical scans returned: {len(hist_resp['items'])} (Total recorded: {hist_resp['total']})"
    )
    # Verify newest first
    assert hist_resp["items"][0]["scan_id"] == sid2
    print(f"  ✓ Newest scan ordered first: {hist_resp['items'][0]['scan_id'][:8]}")

    # --- Step 5: Repository Trend Intelligence API ---
    print("\n[Step 5] Querying Repository Trend Intelligence API...")
    trend_resp = client.get(f"/api/v1/repositories/{repo_id}/trend").json()
    assert trend_resp["total_scans"] >= 2
    assert len(trend_resp["points"]) >= 2
    print(f"  ✓ Trend points returned: {len(trend_resp['points'])} chronological points")
    print(f"  ✓ Message: {trend_resp.get('message') or 'None (Active multi-point trend)'}")

    # --- Step 6: Scan Comparison (Scan 2 vs Scan 1) ---
    print("\n[Step 6] Comparing Scan 2 vs Scan 1 (Identical repository state)...")
    comp_resp = client.get(f"/api/v1/scans/{sid2}/compare/{sid1}")
    assert comp_resp.status_code == 200, f"Comparison failed: {comp_resp.text}"
    comp = comp_resp.json()

    print(f"  ✓ Score Delta: {comp['summary']['score_delta']}")
    print(f"  ✓ Score Direction: {comp['score_comparison']['direction']}")
    print(f"  ✓ Score Explanation: {comp['score_comparison']['explanation']}")
    print(f"  ✓ New Findings Count: {comp['summary']['new_findings_count']}")
    print(f"  ✓ Resolved Findings Count: {comp['summary']['resolved_findings_count']}")
    print(f"  ✓ Persistent Findings Count: {comp['summary']['persistent_findings_count']}")

    assert comp["summary"]["score_delta"] == 0
    assert comp["summary"]["new_findings_count"] == 0
    assert comp["summary"]["resolved_findings_count"] == 0
    assert comp["summary"]["persistent_findings_count"] == len(findings1)
    assert comp["score_comparison"]["direction"] == "unchanged"

    # --- Step 7: Determinism Check ---
    print("\n[Step 7] Verifying Comparison Determinism...")
    comp_repeat = client.get(f"/api/v1/scans/{sid2}/compare/{sid1}").json()
    assert comp == comp_repeat, "Comparison output must be 100% deterministic"
    print("  ✓ Comparison output is 100% byte-for-byte identical across runs")

    # --- Step 8: Synthetic Lifecycle Differential Test ---
    print("\n[Step 8] Verifying Real Lifecycle Detection (New / Resolved / Score Delta)...")
    with tempfile.TemporaryDirectory() as td:
        tmp_repo = Path(td)

        # Scan A: Broad Exception
        (tmp_repo / "main.py").write_text(
            "def run(val):\n"
            "    try:\n"
            "        return val['key']\n"
            "    except Exception:\n"
            "        pass\n"
        )
        r_a = client.post(
            "/api/v1/repositories/scan", json={"path": str(tmp_repo), "repo_name": "Lifecycle_Repo"}
        ).json()
        sid_a = r_a["scan_id"]
        findings_a = client.get(f"/api/v1/scans/{sid_a}/findings").json()
        assert len(findings_a) >= 1

        # Scan B: Fixed
        (tmp_repo / "main.py").write_text("def run(val):\n    return val.get('key')\n")
        r_b = client.post(
            "/api/v1/repositories/scan", json={"path": str(tmp_repo), "repo_name": "Lifecycle_Repo"}
        ).json()
        sid_b = r_b["scan_id"]
        findings_b = client.get(f"/api/v1/scans/{sid_b}/findings").json()
        assert len(findings_b) == 0

        comp_ab = client.get(f"/api/v1/scans/{sid_b}/compare/{sid_a}").json()
        assert comp_ab["summary"]["resolved_findings_count"] >= 1
        assert comp_ab["score_comparison"]["direction"] == "decreased"
        print(
            f"  ✓ Scan A -> Scan B: Debt decreased ({comp_ab['score_comparison']['explanation']})"
        )
        print(f"    Resolved findings: {comp_ab['summary']['resolved_findings_count']}")

        # Scan C: Hardcoded Secret
        (tmp_repo / "main.py").write_text(
            "def run(val):\n"
            "    return val.get('key')\n\n"
            "SECRET_KEY = 'UnsafeHardcodedProductionSecretKeyString987654321'\n"
        )
        r_c = client.post(
            "/api/v1/repositories/scan", json={"path": str(tmp_repo), "repo_name": "Lifecycle_Repo"}
        ).json()
        sid_c = r_c["scan_id"]
        findings_c = client.get(f"/api/v1/scans/{sid_c}/findings").json()
        assert len(findings_c) >= 1

        comp_bc = client.get(f"/api/v1/scans/{sid_c}/compare/{sid_b}").json()
        assert comp_bc["summary"]["new_findings_count"] >= 1
        assert comp_bc["score_comparison"]["direction"] == "increased"
        print(
            f"  ✓ Scan B -> Scan C: Debt increased ({comp_bc['score_comparison']['explanation']})"
        )
        print(f"    New findings: {comp_bc['summary']['new_findings_count']}")

    print("\n" + "=" * 70)
    print("PHASE 10 AUDIT PASSED: ALL INVARIANTS & ACCEPTANCE CRITERIA VERIFIED")
    print("=" * 70)


if __name__ == "__main__":
    run_phase10_verification()

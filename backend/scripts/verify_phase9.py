"""Phase 9 Validation Script: Verifies real Entropy repository scan & determinism."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def run_phase9_verification():
    entropy_repo_path = str(Path(__file__).resolve().parents[2])

    print("=" * 60)
    print("PHASE 9 — REAL REPOSITORY VALIDATION & DETERMINISM AUDIT")
    print("=" * 60)
    print(f"\nTarget Repository: {entropy_repo_path}")

    # --- Scan 1 ---
    print("\n[Step 1] Executing Scan 1 on real Entropy repository...")
    resp1 = client.post(
        "/api/v1/repositories/scan",
        json={"path": entropy_repo_path, "repo_name": "Entropy_Repo_Scan1"},
    )
    assert resp1.status_code == 201, f"Scan 1 failed: {resp1.text}"
    scan1_data = resp1.json()
    scan_id1 = scan1_data["scan_id"]

    findings1 = client.get(f"/api/v1/scans/{scan_id1}/findings").json()
    score1 = client.get(f"/api/v1/scans/{scan_id1}/score").json()

    # --- Scan 2 ---
    print("[Step 2] Executing Scan 2 on real Entropy repository...")
    resp2 = client.post(
        "/api/v1/repositories/scan",
        json={"path": entropy_repo_path, "repo_name": "Entropy_Repo_Scan2"},
    )
    assert resp2.status_code == 201, f"Scan 2 failed: {resp2.text}"
    scan2_data = resp2.json()
    scan_id2 = scan2_data["scan_id"]

    findings2 = client.get(f"/api/v1/scans/{scan_id2}/findings").json()
    score2 = client.get(f"/api/v1/scans/{scan_id2}/score").json()

    # --- Verification ---
    print("\n[Step 3] Verifying Scan Metrics & Repository Statistics:")
    manifest = scan1_data.get("manifest", {}).get("repository", {})
    files_analyzed = len([f for f in scan1_data.get("manifest", {}).get("files", []) if f.get("analysis_supported")])
    total_loc = manifest.get("total_source_loc", 0)
    python_files = scan1_data.get("manifest", {}).get("languages", {}).get("python", 0)

    print(f"  - Total files analyzed: {files_analyzed}")
    print(f"  - Python files analyzed: {python_files}")
    print(f"  - Total source LOC: {total_loc}")

    arch_findings1 = [f for f in findings1 if f["category"] == "architectural_consistency"]
    rule_counts: dict[str, int] = {}
    for f in arch_findings1:
        rule_counts[f["rule_id"]] = rule_counts.get(f["rule_id"], 0) + 1

    print("\n[Step 4] Architectural Consistency Category Findings:")
    print(f"  - Architecture findings count: {len(arch_findings1)}")
    print(f"  - Rule distribution: {rule_counts}")
    arch_score_obj = score1["category_scores"]["architectural_consistency"]
    print(f"  - Architectural category score: {arch_score_obj['score']}")
    print(f"  - Total Entropy score: {score1['total_score']}/100 ({score1['tier']})")

    print("\n[Step 5] All 7 Categories Breakdown:")
    for cat in (
        "error_handling",
        "authentication_consistency",
        "authorization_consistency",
        "input_validation",
        "logging_and_secrets",
        "code_duplication",
        "architectural_consistency",
    ):
        status = score1["category_scores"][cat]["status"]
        score = score1["category_scores"][cat]["score"]
        findings_count = score1["category_scores"][cat]["finding_count"]
        print(f"  - {cat}: status={status}, score={score}, findings={findings_count}")

    print("\n[Step 6] Verifying 100% Determinism Between Scan 1 and Scan 2:")
    assert len(findings1) == len(findings2), "Finding count mismatch between scans!"
    assert score1["total_score"] == score2["total_score"], "Total score mismatch between scans!"
    assert score1["tier"] == score2["tier"], "Score tier mismatch between scans!"

    for f1, f2 in zip(findings1, findings2, strict=True):
        assert f1["id"] == f2["id"], f"Finding ID mismatch: {f1['id']} != {f2['id']}"
        assert f1["fingerprint"] == f2["fingerprint"], f"Fingerprint mismatch: {f1['fingerprint']} != {f2['fingerprint']}"
        assert f1["rule_id"] == f2["rule_id"], f"Rule ID mismatch: {f1['rule_id']} != {f2['rule_id']}"
        assert f1["severity"] == f2["severity"], f"Severity mismatch: {f1['severity']} != {f2['severity']}"
        assert f1["confidence"] == f2["confidence"], f"Confidence mismatch: {f1['confidence']} != {f2['confidence']}"

    for cat in score1["category_scores"]:
        assert score1["category_scores"][cat]["score"] == score2["category_scores"][cat]["score"], f"Category {cat} score mismatch!"
        assert score1["category_scores"][cat]["status"] == score2["category_scores"][cat]["status"], f"Category {cat} status mismatch!"

    print("  ✓ Scan 1 and Scan 2 findings count equal.")
    print("  ✓ Scan 1 and Scan 2 finding IDs 100% identical.")
    print("  ✓ Scan 1 and Scan 2 fingerprints 100% identical.")
    print("  ✓ Scan 1 and Scan 2 scores and categories 100% identical.")

    print("\n" + "=" * 60)
    print("PHASE 9 REAL REPOSITORY VALIDATION COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    run_phase9_verification()

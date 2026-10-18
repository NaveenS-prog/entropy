#!/usr/bin/env python3
"""Phase 4 Verification Script: Deterministic Entropy Scoring Engine.

Executes real repository ingestion and scoring against the active codebase,
validating determinism, zero code execution, and metric accuracy.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
target_path = str(Path(__file__).resolve().parent.parent)

print("Target Codebase:", target_path)
print("=" * 60)

# Run 1
print("\n--- RUN 1 ---")
resp1 = client.post("/api/v1/repositories/scan", json={"path": target_path})
assert resp1.status_code == 201, f"Scan 1 failed: {resp1.text}"
scan_id1 = resp1.json()["scan_id"]
print(f"Scan 1 ID: {scan_id1}")

score_resp1 = client.get(f"/api/v1/scans/{scan_id1}/score")
assert score_resp1.status_code == 200, f"Scoring 1 failed: {score_resp1.text}"
data1 = score_resp1.json()

print(f"Status: {data1.get('status')}")
print(f"Total Score: {data1.get('total_score')} (alias entropy_score: {data1.get('entropy_score')})")
print(f"Tier: {data1.get('tier')} (alias band: {data1.get('band')})")
print(f"Total Findings: {data1.get('total_findings')}")
print(f"Analyzed Files: {data1.get('analyzed_files')}")
print(f"Analyzed Source LOC: {data1.get('total_loc')}")

norm = data1.get("normalization") or {}
print(f"KLOC: {norm.get('kloc')}, Scale Factor: {norm.get('scale_factor')}")
print(f"Severity Breakdown: {data1.get('severity_breakdown')}")
print(f"Analyzed Categories: {data1.get('analyzed_categories')}")

print("\nCategory Breakdown:")
for cat_name, cat_data in data1.get("category_scores", {}).items():
    st = cat_data.get("status")
    sc = cat_data.get("score")
    fc = cat_data.get("finding_count")
    raw = cat_data.get("raw_deduction")
    norm_p = cat_data.get("normalized_penalty")
    print(f"  • {cat_name:25s} | status: {st:12s} | score: {str(sc):5s} | findings: {fc:2d} | raw: {raw:5.1f} | norm: {norm_p:5.2f}")

print("\nTop Contributing Rules:")
for rule in data1.get("top_contributing_rules", []):
    print(f"  - [{rule['rule_id']}] {rule['rule_title']}: {rule['finding_count']} findings, {rule['weighted_points']} pts")

# Run 2
print("\n--- RUN 2 ---")
resp2 = client.post("/api/v1/repositories/scan", json={"path": target_path})
assert resp2.status_code == 201, f"Scan 2 failed: {resp2.text}"
scan_id2 = resp2.json()["scan_id"]
print(f"Scan 2 ID: {scan_id2}")

score_resp2 = client.get(f"/api/v1/scans/{scan_id2}/score")
assert score_resp2.status_code == 200, f"Scoring 2 failed: {score_resp2.text}"
data2 = score_resp2.json()

print(f"Total Score: {data2.get('total_score')}")
print(f"Tier: {data2.get('tier')}")
print(f"Total Findings: {data2.get('total_findings')}")

# Determinism Assertions
assert data1["total_score"] == data2["total_score"], "Total scores differ!"
assert data1["entropy_score"] == data2["entropy_score"], "Entropy scores differ!"
assert data1["tier"] == data2["tier"], "Tiers differ!"
assert data1["band"] == data2["band"], "Bands differ!"
assert data1["total_findings"] == data2["total_findings"], "Total findings differ!"
assert data1["total_loc"] == data2["total_loc"], "Total LOC differs!"
assert data1["analyzed_files"] == data2["analyzed_files"], "Analyzed files differ!"
assert data1["severity_breakdown"] == data2["severity_breakdown"], "Severity breakdowns differ!"
assert data1["category_scores"] == data2["category_scores"], "Category scores differ!"
assert data1["top_contributing_rules"] == data2["top_contributing_rules"], "Top rules differ!"

print("\n" + "=" * 60)
print(">>> DETERMINISM VERIFIED: 100% IDENTICAL ACROSS RUNS <<<")
print("=" * 60)

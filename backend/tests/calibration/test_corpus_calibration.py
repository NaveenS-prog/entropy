"""Calibration corpus validation test suite.

Evaluates Entropy's scoring calibration against real, independently authored open-source
applications recorded in corpus/manifest.json.

Invariants verified:
1. Strict Rank Ordering: Every vulnerable application scores higher than every clean application.
2. Separation Gap: Mean vulnerable score exceeds mean clean score by at least 30 points.
3. Held-Out Generalization: The held-out set preserves strict rank ordering without prior tuning.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.models.domain.enums import DebtScoreTier
from app.services.scan_service import ScanService

CORPUS_DIR = Path(__file__).parent / "corpus"
MANIFEST_FILE = CORPUS_DIR / "manifest.json"


@pytest.fixture(scope="module")
def corpus_manifest():
    if not MANIFEST_FILE.exists():
        pytest.skip("Calibration corpus not present; run tools/fetch_calibration_corpus.py to download.")
    return json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))


def test_corpus_rank_ordering_and_separation(corpus_manifest):
    service = ScanService()
    projects = corpus_manifest.get("projects", [])
    assert len(projects) >= 4, "Corpus must contain at least 4 independent projects"

    results = []
    for p in projects:
        p_dir = CORPUS_DIR / p["relative_dir"]
        if not p_dir.exists():
            pytest.skip(f"Project directory {p_dir} missing; re-run tools/fetch_calibration_corpus.py")

        scan_res = service.execute_scan(p_dir)
        results.append({
            "name": p["name"],
            "type": p["type"],
            "set": p["set"],
            "language": p["language"],
            "score": scan_res.score.total_score,
            "density": scan_res.score.score_density,
            "tier": scan_res.score.tier,
            "floor_applied": scan_res.score.severity_floor_applied,
            "findings_count": len(scan_res.findings),
        })

    vuln_results = [r for r in results if r["type"] == "vulnerable"]
    clean_results = [r for r in results if r["type"] == "clean"]

    assert len(vuln_results) >= 2
    assert len(clean_results) >= 2

    vuln_scores = [r["score"] for r in vuln_results]
    clean_scores = [r["score"] for r in clean_results]

    # 1. Rank Ordering Invariant: Every vulnerable app must score strictly above every clean app
    for v in vuln_results:
        for c in clean_results:
            assert v["score"] > c["score"], (
                f"Rank ordering violated: Vulnerable app '{v['name']}' (score {v['score']}) "
                f"must score above clean app '{c['name']}' (score {c['score']})"
            )

    # 2. Separation Gap Invariant: Mean gap >= 30 points
    mean_vuln = sum(vuln_scores) / len(vuln_scores)
    mean_clean = sum(clean_scores) / len(clean_scores)
    gap = mean_vuln - mean_clean

    assert gap >= 30.0, f"Expected separation gap >= 30.0, but got {gap:.1f}"

    # 3. Clean apps must land in VERY_LOW debt tier
    for c in clean_results:
        assert c["tier"] == DebtScoreTier.VERY_LOW, (
            f"Clean app '{c['name']}' expected VERY_LOW tier, got {c['tier']}"
        )

    # 4. Held-Out Set Separation
    held_out_vuln = [r["score"] for r in vuln_results if r["set"] == "held_out"]
    held_out_clean = [r["score"] for r in clean_results if r["set"] == "held_out"]
    if held_out_vuln and held_out_clean:
        assert min(held_out_vuln) > max(held_out_clean), (
            f"Held-out set rank ordering failed: min vuln {min(held_out_vuln)} <= max clean {max(held_out_clean)}"
        )

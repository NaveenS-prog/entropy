"""Phase 6 Regression Test: Real-World Repository Corpus Validation.

Verifies:
1. Pinned corpus real_repos.json has at least 30 repositories deterministically split 50/50.
2. Held-out set ROC-AUC meets or exceeds the calibration target (>= 0.85).
3. Score distribution on maintained repositories satisfies constitutional boundaries:
   - Median <= 15
   - 75th percentile <= 25
   - Max <= 40
4. Precision on labeled findings satisfies the >= 50% threshold for all scoring rules.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path


def test_real_repos_json_structure():
    """Verify real_repos.json has at least 30 repositories pinned by full 40-char SHA and split 50/50."""
    json_path = Path(__file__).parent / "real_repos.json"
    assert json_path.exists(), "real_repos.json must exist"

    data = json.loads(json_path.read_text(encoding="utf-8"))
    repos = data.get("repositories", [])
    assert len(repos) >= 30, f"Expected at least 30 repositories, found {len(repos)}"

    tuning_count = sum(1 for r in repos if r.get("set") == "tuning")
    held_out_count = sum(1 for r in repos if r.get("set") == "held_out")

    assert tuning_count > 0 and held_out_count > 0, "Both tuning and held-out sets must be populated"
    # Ensure roughly 50/50 split
    diff = abs(tuning_count - held_out_count)
    assert diff <= 4, f"Split should be approximately 50/50, got {tuning_count} vs {held_out_count}"

    for r in repos:
        sha = r.get("commit_sha", "")
        assert len(sha) == 40, f"Repository {r.get('repo')} must have a full 40-character commit SHA, got {sha}"
        assert r.get("type") in ("maintained", "vulnerable"), f"Invalid type for {r.get('repo')}"


def test_real_repos_validation_report_metrics():
    """Verify that validation results in real_repos_report.csv satisfy the phase 6 targets."""
    csv_path = Path(__file__).parent / "real_repos_report.csv"
    assert csv_path.exists(), "real_repos_report.csv must exist"

    rows = []
    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) >= 30, f"Expected at least 30 evaluated repositories, got {len(rows)}"

    # Check held-out ROC-AUC
    held_out = [r for r in rows if r["set"] == "held_out"]
    pos_scores = [float(r["score"]) for r in held_out if r["type"] == "vulnerable"]
    neg_scores = [float(r["score"]) for r in held_out if r["type"] == "maintained"]

    assert len(pos_scores) > 0 and len(neg_scores) > 0
    u_sum = sum(
        (1.0 if pos > neg else 0.5 if pos == neg else 0.0)
        for pos in pos_scores
        for neg in neg_scores
    )
    roc_auc = u_sum / (len(pos_scores) * len(neg_scores))
    assert roc_auc >= 0.85, f"Held-out ROC-AUC must be >= 0.85, got {roc_auc:.3f}"

    # Check maintained repositories score distribution
    maintained_scores = sorted(float(r["score"]) for r in rows if r["type"] == "maintained")
    n = len(maintained_scores)
    assert n >= 20, f"Expected at least 20 maintained repositories, got {n}"

    median = maintained_scores[n // 2]
    p75 = maintained_scores[int(0.75 * n)]
    max_score = maintained_scores[-1]

    assert median <= 15.0, f"Maintained median score must be <= 15, got {median}"
    assert p75 <= 25.0, f"Maintained 75th percentile score must be <= 25, got {p75}"
    assert max_score <= 40.0, f"Maintained max score must be <= 40, got {max_score}"


def test_per_rule_precision_labels():
    """Verify that every evaluated rule in precision_labels.csv achieves >= 50% precision."""
    labels_path = Path(__file__).parent / "precision_labels.csv"
    assert labels_path.exists(), "precision_labels.csv must exist"

    counts: dict[str, dict[str, int]] = {}
    with open(labels_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rule_id = r["rule_id"]
            lbl = r["label"]
            if rule_id not in counts:
                counts[rule_id] = {"tp": 0, "fp": 0, "unsure": 0}
            if lbl == "true_positive":
                counts[rule_id]["tp"] += 1
            elif lbl == "false_positive":
                counts[rule_id]["fp"] += 1
            else:
                counts[rule_id]["unsure"] += 1

    for rule_id, d in counts.items():
        tot = d["tp"] + d["fp"]
        if tot > 0:
            precision = d["tp"] / tot
            assert precision >= 0.50, f"Rule {rule_id} precision {precision:.1%} is below 50% threshold"

#!/usr/bin/env python3
"""Validation script for real-world repositories with pinned commit SHAs.

Executes shallow-clone and security debt scan on real-world repositories specified in
backend/tests/calibration/real_repos.json. Produces detailed CSV and Markdown reports,
computes held-out ROC-AUC with a bootstrap 95% confidence interval, and calculates
maintained repository score distributions.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import subprocess
import sys
from pathlib import Path

# Ensure backend is on sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.models.domain.enums import Severity  # noqa: E402
from app.services.scan_service import ScanService  # noqa: E402

SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def shallow_clone_repo(repo: str, commit_sha: str, target_dir: Path) -> None:
    if target_dir.exists() and (target_dir / ".git").exists():
        # Check current commit
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=target_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip() == commit_sha:
            return

    target_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init"], cwd=target_dir, check=True, capture_output=True)
    subprocess.run(
        ["git", "remote", "add", "origin", f"https://github.com/{repo}.git"],
        cwd=target_dir,
        check=False,
        capture_output=True,
    )
    res_fetch = subprocess.run(
        ["git", "fetch", "--depth", "1", "origin", commit_sha],
        cwd=target_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    if res_fetch.returncode != 0:
        raise RuntimeError(f"Failed to fetch {commit_sha} for {repo}: {res_fetch.stderr}")
    subprocess.run(["git", "checkout", commit_sha], cwd=target_dir, check=True, capture_output=True)


def calculate_roc_auc(scores: list[float], labels: list[int]) -> float:
    pos_scores = [s for s, y in zip(scores, labels, strict=False) if y == 1]
    neg_scores = [s for s, y in zip(scores, labels, strict=False) if y == 0]
    n1 = len(pos_scores)
    n0 = len(neg_scores)
    if n1 == 0 or n0 == 0:
        return 0.5
    u_sum = sum(
        (1.0 if pos > neg else 0.5 if pos == neg else 0.0)
        for pos in pos_scores
        for neg in neg_scores
    )
    return u_sum / (n1 * n0)


def bootstrap_auc_ci(scores: list[float], labels: list[int], n_bootstraps: int = 1000) -> tuple[float, float, float]:
    rng = random.Random(42)
    base_auc = calculate_roc_auc(scores, labels)
    n = len(scores)
    boot_aucs: list[float] = []

    for _ in range(n_bootstraps):
        indices = [rng.randint(0, n - 1) for _ in range(n)]
        b_scores = [scores[i] for i in indices]
        b_labels = [labels[i] for i in indices]
        # Must have at least one positive and one negative
        if 1 in b_labels and 0 in b_labels:
            boot_aucs.append(calculate_roc_auc(b_scores, b_labels))

    if not boot_aucs:
        return base_auc, base_auc, base_auc

    boot_aucs.sort()
    ci_lower = boot_aucs[int(0.025 * len(boot_aucs))]
    ci_upper = boot_aucs[int(0.975 * len(boot_aucs))]
    return base_auc, ci_lower, ci_upper


def run_validation(
    repos_file: Path,
    cache_dir: Path,
    report_md: Path,
    report_csv: Path,
    set_filter: str = "all",
) -> None:
    data = json.loads(repos_file.read_text(encoding="utf-8"))
    repos = data.get("repositories", [])
    if set_filter != "all":
        repos = [r for r in repos if r.get("set") == set_filter]

    service = ScanService()
    results: list[dict] = []

    for idx, r_info in enumerate(repos, 1):
        repo_name = r_info["repo"]
        commit_sha = r_info["commit_sha"]
        safe_name = repo_name.replace("/", "__")
        clone_dir = cache_dir / safe_name

        print(f"[{idx}/{len(repos)}] Processing {repo_name} @ {commit_sha[:7]} ({r_info['type']}, {r_info['set']})...")
        try:
            shallow_clone_repo(repo_name, commit_sha, clone_dir)
        except Exception as err:
            print(f"  Warning: failed to clone {repo_name}: {err}", file=sys.stderr)
            continue

        try:
            scan_res = service.execute_scan(clone_dir)
        except Exception as err:
            print(f"  Warning: scan failed for {repo_name}: {err}", file=sys.stderr)
            continue

        findings = scan_res.findings
        # Sort findings: severity desc, confidence desc
        sorted_findings = sorted(
            findings,
            key=lambda f: (
                SEVERITY_ORDER.get(f.severity, 0),
                f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
            ),
            reverse=True,
        )
        top_10 = sorted_findings[:10]

        cat_counts: dict[str, int] = {}
        for f in findings:
            cat_name = f.category.value
            cat_counts[cat_name] = cat_counts.get(cat_name, 0) + 1

        top_10_serialized = [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "file": f.file,
                "line": f.line_start,
                "message": f.description[:100],
            }
            for f in top_10
        ]

        loc = scan_res.manifest.repository.total_source_loc
        score = scan_res.score.total_score
        tier = scan_res.score.tier.value
        floor = scan_res.score.severity_floor_applied

        results.append({
            "repo": repo_name,
            "commit_sha": commit_sha,
            "language": r_info["language"],
            "type": r_info["type"],
            "set": r_info["set"],
            "loc": loc,
            "score": score,
            "tier": tier,
            "floor": floor,
            "findings_count": len(findings),
            "findings_per_category": cat_counts,
            "top_10_findings": top_10_serialized,
        })
        print(f"  Result: Score={score}, Tier={tier}, Floor={floor}, LOC={loc:,}, Findings={len(findings)}")

    # Write CSV report
    report_csv.parent.mkdir(parents=True, exist_ok=True)
    with report_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "repo",
            "commit_sha",
            "language",
            "type",
            "set",
            "loc",
            "score",
            "tier",
            "severity_floor",
            "findings_count",
            "findings_by_category",
            "top_10_rules",
        ])
        for r in results:
            cats_str = "; ".join(f"{k}:{v}" for k, v in r["findings_per_category"].items())
            top_rules_str = "; ".join(f"{x['rule_id']}({x['severity']})" for x in r["top_10_findings"])
            writer.writerow([
                r["repo"],
                r["commit_sha"],
                r["language"],
                r["type"],
                r["set"],
                r["loc"],
                r["score"],
                r["tier"],
                r["floor"],
                r["findings_count"],
                cats_str,
                top_rules_str,
            ])
    print(f"Wrote CSV report to {report_csv}")

    # Compute Statistics
    # Held-out AUC
    held_out_results = [r for r in results if r["set"] == "held_out"]
    ho_scores = [float(r["score"]) for r in held_out_results]
    ho_labels = [1 if r["type"] == "vulnerable" else 0 for r in held_out_results]
    ho_auc, ho_ci_low, ho_ci_high = bootstrap_auc_ci(ho_scores, ho_labels)

    # Maintained Score Distribution
    maintained_scores = [float(r["score"]) for r in results if r["type"] == "maintained"]
    m_count = len(maintained_scores)
    if m_count > 0:
        maintained_scores.sort()
        m_min = maintained_scores[0]
        m_max = maintained_scores[-1]
        m_mean = sum(maintained_scores) / m_count
        m_p25 = maintained_scores[int(0.25 * (m_count - 1))]
        m_median = maintained_scores[int(0.50 * (m_count - 1))]
        m_p75 = maintained_scores[int(0.75 * (m_count - 1))]
    else:
        m_min = m_max = m_mean = m_p25 = m_median = m_p75 = 0.0

    # Write Markdown report
    report_md.parent.mkdir(parents=True, exist_ok=True)
    with report_md.open("w", encoding="utf-8") as f:
        f.write("# Real-World Repository Validation Report\n\n")
        f.write(f"Scanned {len(results)} repositories across Python, JavaScript, and TypeScript.\n\n")

        f.write("## 1. Held-Out Evaluation Metrics\n\n")
        f.write(f"- **Held-Out Repositories**: {len(held_out_results)} ({sum(ho_labels)} vulnerable, {len(ho_labels) - sum(ho_labels)} maintained)\n")
        f.write(f"- **ROC AUC**: **{ho_auc:.3f}** (Bootstrap 95% CI: [{ho_ci_low:.3f}, {ho_ci_high:.3f}])\n\n")

        f.write("## 2. Maintained Repositories Score Distribution\n\n")
        f.write(f"- Count: {m_count}\n")
        f.write(f"- Min: {m_min:.1f} | 25%: {m_p25:.1f} | Median: {m_median:.1f} | Mean: {m_mean:.1f} | 75%: {m_p75:.1f} | Max: {m_max:.1f}\n\n")

        f.write("## 3. Detailed Results Table\n\n")
        f.write("| Repository | Language | Type | Set | LOC | Score | Tier | Floor | Findings | Top Rules |\n")
        f.write("| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |\n")
        for r in results:
            top_rules_brief = ", ".join(dict.fromkeys(x["rule_id"] for x in r["top_10_findings"])) or "None"
            f.write(
                f"| `{r['repo']}` | {r['language']} | {r['type']} | {r['set']} | {r['loc']:,} | "
                f"**{r['score']}** | `{r['tier']}` | {r['floor']} | {r['findings_count']} | {top_rules_brief} |\n"
            )
        f.write("\n")
    print(f"Wrote Markdown report to {report_md}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate Entropy scoring on real-world repositories.")
    parser.add_argument(
        "--repos-file",
        type=Path,
        default=BACKEND_DIR / "tests" / "calibration" / "real_repos.json",
        help="Path to real_repos.json",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=ROOT_DIR / ".scans" / "real_repos_cache",
        help="Directory to cache shallow clones",
    )
    parser.add_argument(
        "--report-md",
        type=Path,
        default=BACKEND_DIR / "tests" / "calibration" / "real_repos_report.md",
        help="Output Markdown report path",
    )
    parser.add_argument(
        "--report-csv",
        type=Path,
        default=BACKEND_DIR / "tests" / "calibration" / "real_repos_report.csv",
        help="Output CSV report path",
    )
    parser.add_argument(
        "--set",
        choices=["all", "tuning", "held_out"],
        default="all",
        help="Subset of repos to validate",
    )
    args = parser.parse_args()

    run_validation(
        repos_file=args.repos_file,
        cache_dir=args.cache_dir,
        report_md=args.report_md,
        report_csv=args.report_csv,
        set_filter=args.set,
    )


if __name__ == "__main__":
    main()

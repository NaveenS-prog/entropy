"""Formatters for GitHub Check Run payloads and Pull Request Markdown comments.

Follows strict non-negotiable principles:
- Objective, neutral tone.
- Clarifies that score reflects architectural & security debt, not vulnerability exploitability or AI authorship.
- No merge-blocking declarations.
"""

from __future__ import annotations

import collections
from typing import TYPE_CHECKING, Any

from app.comparison.models import ScanComparisonResult

if TYPE_CHECKING:
    from app.policy.models import PolicyEvaluation


def build_check_run_output(
    comparison: ScanComparisonResult,
    pr_number: int,
    dashboard_url: str | None = None,
    policy_evaluation: PolicyEvaluation | None = None,
) -> dict[str, Any]:
    """Build the title, summary, and text for a GitHub Check Run output."""
    summary_data = comparison.summary
    score_comp = comparison.score_comparison

    base_score = summary_data.previous_score if summary_data.previous_score is not None else 0
    head_score = summary_data.current_score if summary_data.current_score is not None else 0
    delta = summary_data.score_delta if summary_data.score_delta is not None else 0

    sign = "+" if delta > 0 else ""
    policy_suffix = f" — Policy: {policy_evaluation.status.value.upper()}" if policy_evaluation else ""
    title = f"Entropy Debt Score: {head_score}/100 ({sign}{delta}){policy_suffix}"

    # Changed categories
    changed_cats = []
    for cat_comp in comparison.category_comparisons.values():
        if cat_comp.finding_count_delta != 0 or (cat_comp.score_delta and cat_comp.score_delta != 0):
            changed_cats.append(cat_comp.category_name)

    cat_changes_str = ", ".join(changed_cats) if changed_cats else "None"

    policy_summary_str = ""
    if policy_evaluation:
        policy_summary_str = (
            f"\n**Entropy Policy**: **{policy_evaluation.status.value.upper()}** "
            f"({len(policy_evaluation.violations)} violation(s), {len(policy_evaluation.warnings)} warning(s))\n"
        )

    summary = (
        f"### Entropy Architectural & Security Debt Analysis (PR #{pr_number})\n\n"
        f"- **Head Score**: {head_score} / 100 ({score_comp.current_band.value if score_comp.current_band else 'unrated'})\n"
        f"- **Base Score**: {base_score} / 100 ({score_comp.previous_band.value if score_comp.previous_band else 'unrated'})\n"
        f"- **Score Delta**: {sign}{delta} points\n"
        f"{policy_summary_str}\n"
        f"**Finding Lifecycle Breakdown**:\n"
        f"- **New Debt**: {summary_data.new_findings_count} finding(s)\n"
        f"- **Resolved**: {summary_data.resolved_findings_count} finding(s)\n"
        f"- **Persistent**: {summary_data.persistent_findings_count} finding(s)\n"
        f"- **Affected Categories**: {cat_changes_str}\n"
    )

    if dashboard_url:
        summary += f"\n[👉 View Full Entropy Comparison]({dashboard_url})\n"

    # Detail markdown text
    text_lines = ["### New Debt Findings Introduced:"]
    if comparison.new_findings:
        for f in comparison.new_findings[:15]:
            text_lines.append(f"- **{f.rule_id}** (`{f.severity.value}`): {f.title} in `{f.file}:{f.line_start}`")
        if len(comparison.new_findings) > 15:
            text_lines.append(f"- *...and {len(comparison.new_findings) - 15} more new finding(s)*")
    else:
        text_lines.append("*(No new architectural or security debt introduced in this PR)*")

    if comparison.resolved_findings:
        text_lines.append("\n### Debt Findings Resolved in this PR:")
        for f in comparison.resolved_findings[:10]:
            text_lines.append(f"- **{f.rule_id}**: {f.title} in `{f.file}:{f.line_start}`")
        if len(comparison.resolved_findings) > 10:
            text_lines.append(f"- *...and {len(comparison.resolved_findings) - 10} more resolved finding(s)*")

    if policy_evaluation:
        text_lines.append("\n### 🛡️ Policy Evaluation Breakdown:")
        if policy_evaluation.violations:
            text_lines.append("\n**Blocking Policy Violations:**")
            for v in policy_evaluation.violations:
                text_lines.append(f"- ❌ **{v.rule_name}**: {v.message}")
        if policy_evaluation.warnings:
            text_lines.append("\n**Policy Warnings:**")
            for w in policy_evaluation.warnings:
                text_lines.append(f"- ⚠️ **{w.rule_name}**: {w.message}")
        if not policy_evaluation.violations and not policy_evaluation.warnings:
            text_lines.append("*(All evaluated policy rules satisfied)*")

    text = "\n".join(text_lines)

    return {
        "title": title,
        "summary": summary,
        "text": text,
    }


def build_pr_comment_markdown(
    comparison: ScanComparisonResult,
    pr_number: int,
    dashboard_url: str | None = None,
    policy_evaluation: PolicyEvaluation | None = None,
) -> str:
    """Build Markdown body for an informational Pull Request comment."""
    summary_data = comparison.summary
    score_comp = comparison.score_comparison

    base_score = summary_data.previous_score if summary_data.previous_score is not None else 0
    head_score = summary_data.current_score if summary_data.current_score is not None else 0
    delta = summary_data.score_delta if summary_data.score_delta is not None else 0
    sign = "+" if delta > 0 else ""

    # Group new findings by rule
    new_by_rule: dict[str, int] = collections.defaultdict(int)
    for f in comparison.new_findings:
        new_by_rule[f.rule_id] += 1

    # Group resolved findings by rule
    resolved_by_rule: dict[str, int] = collections.defaultdict(int)
    for f in comparison.resolved_findings:
        resolved_by_rule[f.rule_id] += 1

    comment_lines = [
        "<!-- entropy-pr-report -->",
        "## 🔍 Entropy Architectural & Security Debt Report",
        "",
        f"| Metric | Base (`{summary_data.previous_scan_id[:8]}`) | PR (`{summary_data.current_scan_id[:8]}`) | Delta |",
        "| :--- | :---: | :---: | :---: |",
        f"| **Entropy Score** | **{base_score}** / 100 | **{head_score}** / 100 | **{sign}{delta}** |",
        f"| **Total Findings** | {summary_data.resolved_findings_count + summary_data.persistent_findings_count} | {summary_data.total_current_findings} | {summary_data.new_findings_count - summary_data.resolved_findings_count:+d} |",
    ]

    if policy_evaluation:
        status_emoji = "✅" if policy_evaluation.status == "pass" else ("⚠️" if policy_evaluation.status == "warn" else "❌")
        comment_lines.append(
            f"| **Policy Decision** | — | **{status_emoji} {policy_evaluation.status.value.upper()}** | "
            f"{len(policy_evaluation.violations)} violation(s), {len(policy_evaluation.warnings)} warning(s) |"
        )

    comment_lines.extend([
        "",
        f"**Debt Movement Summary**: {score_comp.explanation}",
        "",
    ])

    if policy_evaluation and policy_evaluation.violations:
        comment_lines.append("### 🚫 Policy Violations")
        for v in policy_evaluation.violations:
            comment_lines.append(f"- ❌ **{v.rule_name}**: {v.message}")
        comment_lines.append("")

    if policy_evaluation and policy_evaluation.warnings:
        comment_lines.append("### ⚠️ Policy Warnings")
        for w in policy_evaluation.warnings:
            comment_lines.append(f"- ⚠️ **{w.rule_name}**: {w.message}")
        comment_lines.append("")

    if new_by_rule:
        comment_lines.append("### ⚠️ New Debt Findings")
        for rule_id, count in sorted(new_by_rule.items()):
            comment_lines.append(f"- **{rule_id}** ×{count}")
        comment_lines.append("")
    else:
        comment_lines.extend(["### ✅ No New Debt Introduced", ""])

    if resolved_by_rule:
        comment_lines.append("### 🎯 Resolved Debt Findings")
        for rule_id, count in sorted(resolved_by_rule.items()):
            comment_lines.append(f"- **{rule_id}** ×{count}")
        comment_lines.append("")

    comment_lines.extend([
        f"**Persistent Debt**: {summary_data.persistent_findings_count} existing finding(s) unchanged.",
        "",
    ])

    if dashboard_url:
        comment_lines.append(f"[👉 **View Full Interactive Comparison in Entropy Dashboard**]({dashboard_url})")

    return "\n".join(comment_lines)

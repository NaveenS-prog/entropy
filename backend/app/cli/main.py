"""Entropy Command-Line Interface.

Provides deterministic CLI tools for developer local workflows, CI/CD gates,
scanning, findings inspection, comparison, AI advisory explanation, and policy evaluation.

Exit Codes:
  0 = PASS (or WARN when --fail-on-warn is omitted)
  1 = POLICY FAIL (or WARN when --fail-on-warn is provided)
  2 = CONFIGURATION / ARGUMENT / VALIDATION ERROR
  3 = ANALYSIS / SYSTEM / DATA NOT FOUND ERROR
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

from app.comparison.models import ScanComparisonResult
from app.comparison.service import comparison_service
from app.core.config import settings
from app.core.errors import RepositoryError
from app.models.domain.enums import DebtCategory, Severity
from app.models.domain.finding import Finding
from app.models.domain.scan import RepositoryScanResult
from app.policy.evaluator import PolicyEvaluator
from app.policy.models import PolicyConfig, PolicyEvaluation, PolicyStatus
from app.policy.parser import PolicyConfigurationError, get_default_policy, parse_policy_file
from app.policy.service import policy_service
from app.sarif.formatter import generate_sarif_log
from app.scoring.service import scoring_service
from app.services.analysis_service import analysis_service
from app.services.repository_service import repository_service

EXIT_PASS = 0
EXIT_POLICY_FAIL = 1
EXIT_CONFIG_ERROR = 2
EXIT_SYSTEM_ERROR = 3

CATEGORY_ORDER = [
    DebtCategory.ERROR_HANDLING,
    DebtCategory.AUTHENTICATION_CONSISTENCY,
    DebtCategory.AUTHORIZATION_CONSISTENCY,
    DebtCategory.INPUT_VALIDATION,
    DebtCategory.LOGGING_AND_SECRETS,
    DebtCategory.CODE_DUPLICATION,
    DebtCategory.ARCHITECTURAL_CONSISTENCY,
]

CATEGORY_LABELS = {
    DebtCategory.ERROR_HANDLING: "Error Handling",
    DebtCategory.AUTHENTICATION_CONSISTENCY: "Authentication",
    DebtCategory.AUTHORIZATION_CONSISTENCY: "Authorization",
    DebtCategory.INPUT_VALIDATION: "Input Validation",
    DebtCategory.LOGGING_AND_SECRETS: "Logging & Secrets",
    DebtCategory.CODE_DUPLICATION: "Code Duplication",
    DebtCategory.ARCHITECTURAL_CONSISTENCY: "Architecture",
}


def _run_single_scan_pipeline(
    repo_path: str | Path,
    repo_name: str | None = None,
    category: DebtCategory | None = None,
    severity: Severity | None = None,
    rule_id: str | None = None,
    file_filter: str | None = None,
) -> tuple[RepositoryScanResult, list[Finding]]:
    """Execute exactly ONE safe scan, ONE analysis pass, and ONE scoring pass.

    Returns the updated RepositoryScanResult and the findings.
    """
    path_str = str(repo_path)
    # 1. Execute ingestion / discovery
    scan = repository_service.execute_scan(repo_path=path_str, repo_name=repo_name)

    # 2. Execute static AST analysis across all registered analyzers
    findings = analysis_service.analyze_scan(
        scan_id=scan.scan_id,
        category=category,
        severity=severity,
        rule_id=rule_id,
        file_filter=file_filter,
    )

    # 3. Calculate deterministic Entropy Debt score
    scoring_service.calculate_scan_score(scan_id=scan.scan_id)

    # 4. Refresh scan instance with score and findings attached
    refreshed_scan = repository_service.get_scan(scan.scan_id) or scan
    return refreshed_scan, findings


def format_scan_text(scan: RepositoryScanResult) -> str:
    """Format RepositoryScanResult into human-readable text output."""
    lines: list[str] = [
        "Entropy Scan",
        "────────────────────────────",
        f"Repository: {scan.repository.path}",
        "",
        f"Files discovered: {scan.repository.total_files}",
        f"Files analyzed: {scan.repository.scannable_files}",
    ]
    if scan.repository.total_loc > 0:
        lines.append(f"Lines of code: {scan.repository.total_loc}")
    lines.append(f"Findings: {len(scan.findings)}")
    supp_count = getattr(scan, "suppressed_findings_count", 0)
    if supp_count > 0:
        lines.append(f"Suppressed findings: {supp_count}")
    lines.append("")

    score_val = scan.score.total_score if scan.score else 0
    tier_val = scan.score.tier.value if scan.score else "Unknown"
    # Pretty title for band
    tier_title = " ".join(word.capitalize() for word in tier_val.replace("_", " ").split())
    lines.append(f"Entropy Score: {score_val} / 100")
    lines.append(f"Band: {tier_title}")
    lines.append("")
    lines.append("Categories:")
    lines.append("")

    for cat in CATEGORY_ORDER:
        label = CATEGORY_LABELS.get(cat, cat.value)
        cat_breakdown = scan.score.category_scores.get(cat) if scan.score else None
        if cat_breakdown and cat_breakdown.score is not None:
            score_str = f"{cat_breakdown.score:.1f}"
        else:
            score_str = "0.0"
        lines.append(f"  {label:<24} {score_str:>6}")

    return "\n".join(lines)


def format_scan_json_dict(scan: RepositoryScanResult) -> dict[str, Any]:
    """Build deterministic, stable JSON dict for scan output."""
    categories_dict: dict[str, Any] = {}
    for cat in CATEGORY_ORDER:
        cat_breakdown = scan.score.category_scores.get(cat) if scan.score else None
        categories_dict[cat.value] = {
            "name": CATEGORY_LABELS.get(cat, cat.value),
            "score": round(cat_breakdown.score, 1) if (cat_breakdown and cat_breakdown.score is not None) else 0.0,
            "status": cat_breakdown.status.value if cat_breakdown else "not_analyzed",
            "findings_count": cat_breakdown.finding_count if cat_breakdown else 0,
            "weight": round(cat_breakdown.weight, 2) if cat_breakdown else 0.0,
        }

    # Deterministically order findings by file, line_start, line_end, id
    sorted_findings = sorted(
        scan.findings,
        key=lambda f: (f.file, f.line_start, f.line_end, f.id),
    )
    findings_list = [
        {
            "id": f.id,
            "rule_id": f.rule_id,
            "title": f.title,
            "category": f.category.value,
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "file": f.file,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "column_start": f.column_start,
            "column_end": f.column_end,
            "symbol": f.symbol,
            "message": f.description,
            "fingerprint": f.fingerprint,
            "is_suppressed": getattr(f, "is_suppressed", False),
            "suppression_source": getattr(f, "suppression_source", None),
            "suppression_reason": getattr(f, "suppression_reason", None),
            "status": getattr(f, "status", None),
        }
        for f in sorted_findings
    ]

    return {
        "repository": {
            "name": scan.repository.name,
            "path": scan.repository.path,
            "repository_id": scan.repository.repository_id,
            "branch": scan.repository.branch,
            "commit_hash": scan.repository.commit_hash,
            "is_dirty": getattr(scan.repository, "is_dirty", False),
            "project_id": getattr(scan.repository, "project_id", None),
        },
        "files": {
            "discovered": scan.repository.total_files,
            "analyzed": scan.repository.scannable_files,
            "lines_of_code": scan.repository.total_loc,
        },
        "score": {
            "total_score": scan.score.total_score if scan.score else 0,
            "band": scan.score.tier.value if scan.score else "unknown",
            "findings_count": len(scan.findings),
            "suppressed_findings_count": getattr(scan, "suppressed_findings_count", 0),
        },
        "config_hash": getattr(scan, "config_hash", None),
        "categories": categories_dict,
        "findings": findings_list,
    }


def format_check_text(
    scan: RepositoryScanResult,
    evaluation: PolicyEvaluation,
    comparison: Any = None,
) -> str:
    """Format check output into human-readable text."""
    lines: list[str] = [
        "Entropy Check",
        "────────────────────────────",
    ]
    score_val = scan.score.total_score if scan.score else 0
    tier_val = scan.score.tier.value if scan.score else "Unknown"
    tier_title = " ".join(word.capitalize() for word in tier_val.replace("_", " ").split())

    lines.append(f"Score: {score_val} / 100")
    lines.append(f"Band: {tier_title}")
    lines.append("")
    lines.append(f"Findings: {len(scan.findings)}")
    supp_count = getattr(scan, "suppressed_findings_count", 0)
    if supp_count > 0:
        lines.append(f"Suppressed findings: {supp_count}")
    lines.append("")

    if comparison is not None:
        lines.append("Baseline Comparison:")
        lines.append("────────────────────────────")
        lines.append(f"Baseline: {comparison.baseline_score} -> Current: {comparison.current_score} (Delta: {comparison.score_delta:+d})")
        lines.append(f"Findings: +{comparison.new_count} new, -{comparison.resolved_count} resolved, {comparison.unchanged_count} unchanged, {comparison.suppressed_count} suppressed")
        lines.append("")

    lines.append(f"Policy: {evaluation.policy_name} (status: {evaluation.status.value.upper()})")

    if evaluation.violations:
        lines.append(f"Violations: {len(evaluation.violations)}")
        for v in evaluation.violations:
            lines.append(f"  ❌ [{v.rule_name}]: {v.message}")

    if evaluation.warnings:
        lines.append(f"Warnings: {len(evaluation.warnings)}")
        for w in evaluation.warnings:
            lines.append(f"  ⚠️  [{w.rule_name}]: {w.message}")

    lines.append("")
    result_str = "FAIL" if evaluation.status == PolicyStatus.FAIL else "PASS"
    lines.append(f"Result: {result_str}")
    lines.append(f"Exit code: {EXIT_POLICY_FAIL if result_str == 'FAIL' else EXIT_PASS}")

    return "\n".join(lines)


def format_findings_text(findings: list[Finding]) -> str:
    """Format list of findings into human-readable text."""
    if not findings:
        return "No findings discovered."

    # Sort deterministically
    sorted_findings = sorted(
        findings,
        key=lambda f: (f.severity.value, f.file, f.line_start, f.id),
    )

    lines: list[str] = [
        "Entropy Findings",
        "────────────────────────────",
        f"Total Findings: {len(sorted_findings)}",
        "",
    ]

    for f in sorted_findings:
        loc = f"{f.file}:{f.line_start}"
        status_tag = f" [{f.status.upper()}]" if getattr(f, "status", None) else ""
        supp_tag = " (SUPPRESSED)" if getattr(f, "is_suppressed", False) else ""
        lines.append(f"[{f.severity.value.upper()}]{status_tag}{supp_tag} {f.rule_id} ({f.category.value})")
        lines.append(f"  Location: {loc}")
        lines.append(f"  Message:  {f.title}")
        if getattr(f, "suppression_reason", None):
            lines.append(f"  Suppressed: {f.suppression_reason}")
        if f.symbol:
            lines.append(f"  Symbol:   {f.symbol}")
        lines.append("")

    return "\n".join(lines).rstrip()


def format_comparison_text(comp: ScanComparisonResult) -> str:
    """Format comparison result into human-readable text."""
    s = comp.summary
    delta_str = f"{s.score_delta:+d}" if s.score_delta is not None else "0"
    lines: list[str] = [
        "Entropy Comparison",
        "────────────────────────────",
        f"Base:  {s.previous_score if s.previous_score is not None else 'N/A'}",
        f"Head:  {s.current_score if s.current_score is not None else 'N/A'}",
        f"Delta: {delta_str}",
        "",
        f"New:        {s.new_findings_count}",
        f"Resolved:   {s.resolved_findings_count}",
        f"Persistent: {s.persistent_findings_count}",
        "",
        "Category Deltas:",
    ]

    for cat in CATEGORY_ORDER:
        cat_key = cat.value
        cat_comp = comp.category_comparisons.get(cat_key)
        if cat_comp:
            c_delta = f"{cat_comp.score_delta:+0.1f}" if cat_comp.score_delta is not None else "N/A"
            lines.append(f"  {cat_comp.category_name:<26} {c_delta:>7}")

    return "\n".join(lines)


def format_evaluation_text(evaluation: PolicyEvaluation) -> str:
    """Format PolicyEvaluation into human-readable CI terminal output."""
    lines = []
    lines.append("=" * 60)
    lines.append(f"ENTROPY POLICY EVALUATION: {evaluation.status.value.upper()}")
    lines.append(f"Policy: {evaluation.policy_name} (v{evaluation.policy_version})")
    lines.append(f"Score: {evaluation.score}/100")
    if evaluation.base_score is not None:
        delta_str = f"{evaluation.score_delta:+d}" if evaluation.score_delta is not None else "0"
        lines.append(f"Base Score: {evaluation.base_score}/100  |  Delta: {delta_str}")
    if evaluation.new_findings_count is not None:
        lines.append(f"New Findings: {evaluation.new_findings_count}")
    lines.append("-" * 60)

    if evaluation.violations:
        lines.append("BLOCKING VIOLATIONS:")
        for v in evaluation.violations:
            lines.append(f"  ❌ [{v.rule_name}] ({v.rule_type}): {v.message}")
            if v.finding_ids:
                sample_ids = ", ".join(v.finding_ids[:5])
                suffix = f"... ({len(v.finding_ids)} total)" if len(v.finding_ids) > 5 else ""
                lines.append(f"     Findings: {sample_ids}{suffix}")

    if evaluation.warnings:
        lines.append("WARNINGS:")
        for w in evaluation.warnings:
            lines.append(f"  ⚠️  [{w.rule_name}] ({w.rule_type}): {w.message}")

    if evaluation.passed_rules:
        lines.append(f"PASSED RULES ({len(evaluation.passed_rules)}):")
        for p in evaluation.passed_rules:
            lines.append(f"  ✓  [{p.rule_name}]: {p.message}")

    if evaluation.not_applicable_rules:
        lines.append(f"NOT APPLICABLE RULES ({len(evaluation.not_applicable_rules)}):")
        for na in evaluation.not_applicable_rules:
            lines.append(f"  -  [{na.rule_name}]: {na.message}")

    lines.append("=" * 60)
    lines.append(f"Decision: {evaluation.summary}")
    lines.append("=" * 60)
    return "\n".join(lines)


# -----------------------------------------------------------------------------
# COMMAND IMPLEMENTATIONS
# -----------------------------------------------------------------------------

def cmd_version(args: argparse.Namespace) -> int:
    """Print the single source-of-truth Entropy version."""
    if not getattr(args, "quiet", False):
        print(f"entropy {settings.VERSION}")
    else:
        print(settings.VERSION)
    return EXIT_PASS


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute repository scan, static analysis, and scoring."""
    target_path = Path(args.path)
    if not target_path.exists():
        print(f"Error: Target path '{args.path}' does not exist.", file=sys.stderr)
        return EXIT_SYSTEM_ERROR

    start_time = time.perf_counter()
    try:
        scan, findings = _run_single_scan_pipeline(repo_path=target_path)
    except RepositoryError as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR
    except Exception as exc:
        print(f"Unexpected scan error: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR

    elapsed = time.perf_counter() - start_time

    if getattr(args, "verbose", False) and not getattr(args, "quiet", False):
        print(f"[VERBOSE] Scanned {scan.repository.total_files} files in {elapsed:.2f}s", file=sys.stderr)
        print(f"[VERBOSE] Analyzed files: {scan.repository.scannable_files}, LOC: {scan.repository.total_loc}", file=sys.stderr)
        print(f"[VERBOSE] Generated {len(findings)} findings", file=sys.stderr)

    fmt = getattr(args, "format", "text")
    if fmt == "json":
        data = format_scan_json_dict(scan)
        print(json.dumps(data, indent=2))
    elif fmt == "sarif":
        sarif_data = generate_sarif_log(scan, findings)
        print(json.dumps(sarif_data, indent=2))
    else:
        if not getattr(args, "quiet", False):
            print(format_scan_text(scan))

    return EXIT_PASS


def cmd_check(args: argparse.Namespace) -> int:
    """Execute scan, score, and evaluate against policy (PRIMARY developer command)."""
    target_path = Path(args.path)
    if not target_path.exists():
        print(f"Error: Target path '{args.path}' does not exist.", file=sys.stderr)
        return EXIT_SYSTEM_ERROR

    # 1. Load Project Config if present
    from app.core.project_config import load_project_config

    cfg = None
    try:
        cfg = load_project_config(target_path)
    except Exception as exc:
        print(f"Configuration error in .entropy.yml: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    # 2. Resolve Policy
    policy: PolicyConfig
    policy_path = getattr(args, "policy", None)
    if not policy_path and cfg and cfg.policy.file:
        policy_path = str(target_path / cfg.policy.file)

    if policy_path:
        try:
            policy = parse_policy_file(policy_path)
        except PolicyConfigurationError as exc:
            print(f"Policy configuration error: {exc.message}", file=sys.stderr)
            return EXIT_CONFIG_ERROR
        except Exception as exc:
            print(f"Failed to read policy file: {exc}", file=sys.stderr)
            return EXIT_CONFIG_ERROR
    else:
        policy = get_default_policy()

    # 3. Run ONE scan pass, ONE analysis pass, ONE scoring pass
    try:
        scan, findings = _run_single_scan_pipeline(repo_path=target_path)
    except RepositoryError as exc:
        print(f"Check failed: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR
    except Exception as exc:
        print(f"Unexpected check error: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR

    # 4. Baseline Comparison (if enabled)
    baseline_mode = cfg.scoring.baseline if cfg else "auto"
    baseline_file = cfg.scoring.baseline_file if cfg else ".entropy-baseline.json"
    baseline_path = target_path / baseline_file

    baseline_comp = None
    scan_comp = None
    if baseline_mode != "off":
        if baseline_path.is_file():
            try:
                from app.core.baseline import compare_with_baseline, load_baseline_file

                baseline = load_baseline_file(baseline_path)
                baseline_comp = compare_with_baseline(scan, baseline)
                scan_comp = baseline_comp.to_scan_comparison(scan, baseline)
            except Exception as b_err:
                print(f"Warning: Failed to load baseline: {b_err}", file=sys.stderr)
                if baseline_mode == "strict":
                    return EXIT_CONFIG_ERROR
        elif baseline_mode == "strict":
            print(
                f"Error: Strict baseline mode enabled, but baseline file not found at '{baseline_path}'.",
                file=sys.stderr,
            )
            return EXIT_CONFIG_ERROR

    # 5. Evaluate scan against policy
    evaluation = policy_service.evaluate_scan_obj(scan=scan, policy=policy, comparison=scan_comp)

    # 6. Format Output
    fmt = getattr(args, "format", "text")
    if fmt == "json":
        out = {
            "score": scan.score.total_score if scan.score else 0,
            "band": scan.score.tier.value if scan.score else "unknown",
            "findings_count": len(findings),
            "suppressed_findings_count": getattr(scan, "suppressed_findings_count", 0),
            "policy": evaluation.model_dump(mode="json"),
            "result": "FAIL" if evaluation.status == PolicyStatus.FAIL else "PASS",
        }
        if baseline_comp:
            out["baseline"] = {
                "baseline_score": baseline_comp.baseline_score,
                "current_score": baseline_comp.current_score,
                "score_delta": baseline_comp.score_delta,
                "new_count": baseline_comp.new_count,
                "resolved_count": baseline_comp.resolved_count,
                "unchanged_count": baseline_comp.unchanged_count,
                "suppressed_count": baseline_comp.suppressed_count,
            }
        print(json.dumps(out, indent=2))
    elif fmt == "sarif":
        sarif_data = generate_sarif_log(scan, findings)
        print(json.dumps(sarif_data, indent=2))
    else:
        if not getattr(args, "quiet", False):
            print(format_check_text(scan, evaluation, comparison=baseline_comp))

    # 7. Exit Code Semantics
    if evaluation.status == PolicyStatus.FAIL:
        return EXIT_POLICY_FAIL
    elif evaluation.status == PolicyStatus.WARN and getattr(args, "fail_on_warn", False):
        return EXIT_POLICY_FAIL
    else:
        return EXIT_PASS


def cmd_findings(args: argparse.Namespace) -> int:
    """List findings for a repository with optional filters."""
    target_path = Path(args.path)
    if not target_path.exists():
        print(f"Error: Target path '{args.path}' does not exist.", file=sys.stderr)
        return EXIT_SYSTEM_ERROR

    sev_filter = None
    if getattr(args, "severity", None):
        try:
            sev_filter = Severity(args.severity.lower())
        except ValueError:
            print(f"Error: Invalid severity '{args.severity}'. Choose from: critical, high, medium, low, info.", file=sys.stderr)
            return EXIT_CONFIG_ERROR

    cat_filter = None
    if getattr(args, "category", None):
        try:
            cat_filter = DebtCategory(args.category)
        except ValueError:
            print(f"Error: Invalid category '{args.category}'.", file=sys.stderr)
            return EXIT_CONFIG_ERROR

    try:
        scan, findings = _run_single_scan_pipeline(
            repo_path=target_path,
            category=cat_filter,
            severity=sev_filter,
            rule_id=getattr(args, "rule", None),
            file_filter=getattr(args, "file", None),
        )
    except RepositoryError as exc:
        print(f"Findings query failed: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR
    except Exception as exc:
        print(f"Unexpected findings error: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR

    # Phase 15 filters: --new and --suppressed
    is_new = getattr(args, "new", False)
    is_suppressed = getattr(args, "suppressed", False)

    if is_new:
        from app.core.project_config import load_project_config

        cfg = load_project_config(target_path)
        baseline_file = cfg.scoring.baseline_file if cfg else ".entropy-baseline.json"
        baseline_path = target_path / baseline_file
        if baseline_path.is_file():
            from app.core.baseline import compare_with_baseline, load_baseline_file

            baseline = load_baseline_file(baseline_path)
            comp_res = compare_with_baseline(scan, baseline, current_findings=findings)
            findings = comp_res.new_findings
        else:
            findings = [f for f in findings if not getattr(f, "is_suppressed", False)]
    elif is_suppressed:
        findings = [f for f in findings if getattr(f, "is_suppressed", False)]
    else:
        # Default: show active findings
        findings = [f for f in findings if not getattr(f, "is_suppressed", False)]

    fmt = getattr(args, "format", "text")
    if fmt == "json":
        sorted_findings = sorted(
            findings,
            key=lambda f: (f.file, f.line_start, f.line_end, f.id),
        )
        print(json.dumps([f.model_dump(mode="json") for f in sorted_findings], indent=2))
    elif fmt == "sarif":
        sarif_data = generate_sarif_log(scan, findings)
        print(json.dumps(sarif_data, indent=2))
    else:
        if not getattr(args, "quiet", False):
            print(format_findings_text(findings))

    return EXIT_PASS


def cmd_compare(args: argparse.Namespace) -> int:
    """Compare two scans or repository paths."""
    base_target = args.base
    head_target = args.head

    base_scan: RepositoryScanResult | None = None
    head_scan: RepositoryScanResult | None = None

    try:
        # Check if base_target is a local directory or a scan ID
        base_path = Path(base_target)
        if base_path.exists() and base_path.is_dir():
            base_scan, _ = _run_single_scan_pipeline(base_path)
        else:
            base_scan = repository_service.get_scan(base_target)
            if not base_scan:
                print(f"Error: Base target '{base_target}' is neither an existing directory nor a known scan ID.", file=sys.stderr)
                return EXIT_SYSTEM_ERROR

        head_path = Path(head_target)
        if head_path.exists() and head_path.is_dir():
            head_scan, _ = _run_single_scan_pipeline(head_path)
        else:
            head_scan = repository_service.get_scan(head_target)
            if not head_scan:
                print(f"Error: Head target '{head_target}' is neither an existing directory nor a known scan ID.", file=sys.stderr)
                return EXIT_SYSTEM_ERROR

        comp = comparison_service.compare_scans(current_scan=head_scan, previous_scan=base_scan)
    except Exception as exc:
        print(f"Comparison error: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR

    fmt = getattr(args, "format", "text")
    if fmt == "json":
        print(comp.model_dump_json(indent=2))
    else:
        if not getattr(args, "quiet", False):
            print(format_comparison_text(comp))

    return EXIT_PASS


def cmd_explain(args: argparse.Namespace) -> int:
    """Explain a specific finding using advisory AI service."""
    finding_id = args.finding_id

    # 1. Check AI_ENABLED configuration first for graceful messaging
    if not settings.AI_ENABLED:
        print("Notice: AI explanation layer is currently disabled.", file=sys.stderr)
        print("To enable AI advisory explanations, set AI_ENABLED=true and configure an AI provider.", file=sys.stderr)
        return EXIT_PASS

    try:
        from app.ai.service import AIDisabledError, FindingNotFoundError, ai_service

        explanation = asyncio.run(
            ai_service.explain_finding(
                finding_id=finding_id,
                scan_id=getattr(args, "scan_id", None),
            )
        )

        lines: list[str] = [
            "Entropy AI Advisory Explanation",
            "────────────────────────────",
            f"Finding: {explanation.finding_id}",
            f"Summary: {explanation.summary}",
            "",
            "Why It Matters:",
            explanation.why_it_matters,
            "",
            "Architectural Impact:",
            explanation.architectural_impact,
            "",
            "Recommended Remediation:",
            explanation.remediation,
            "",
            "Suggested Pattern:",
            explanation.suggested_pattern,
            "",
            "────────────────────────────",
            "Notice: AI-generated content is strictly advisory and does not affect",
            "Entropy findings, score, policy evaluation, or CI exit codes.",
        ]
        print("\n".join(lines))
        return EXIT_PASS

    except FindingNotFoundError:
        print(f"Error: Finding with ID '{finding_id}' not found.", file=sys.stderr)
        return EXIT_SYSTEM_ERROR
    except AIDisabledError as exc:
        print(f"Notice: {exc}", file=sys.stderr)
        return EXIT_PASS
    except Exception as exc:
        print(f"AI service unavailable: {exc}", file=sys.stderr)
        print("Note: Entropy core static analysis and CI exit codes remain unaffected.", file=sys.stderr)
        return EXIT_PASS


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize a minimal, clean .entropy.yml configuration."""
    target_dir = Path(getattr(args, "path", ".")).resolve()
    if not target_dir.exists():
        print(f"Error: Target directory '{target_dir}' does not exist.", file=sys.stderr)
        return EXIT_SYSTEM_ERROR

    config_path = target_dir / ".entropy.yml"
    config_alt = target_dir / ".entropy.yaml"
    if config_path.exists() or config_alt.exists():
        print(f"Error: Configuration file already exists at {config_path}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    project_name = target_dir.name or "entropy-project"
    template = f"""# Entropy Project Configuration (.entropy.yml)
version: 1

project:
  name: {project_name}

analysis:
  languages:
    - python
    - javascript
    - typescript
  exclude:
    - "tests/**"
    - "docs/**"

scoring:
  baseline: auto
  baseline_file: .entropy-baseline.json

policy:
  file: null

output:
  format: text

ignore:
  rules: []
  findings: []
"""
    try:
        config_path.write_text(template, encoding="utf-8")
        if not getattr(args, "quiet", False):
            print(f"Initialized Entropy project configuration at {config_path}")
        return EXIT_PASS
    except Exception as exc:
        print(f"Error: Failed to write configuration file: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def cmd_config_validate(args: argparse.Namespace) -> int:
    """Validate .entropy.yml configuration strictly."""
    target_input = Path(getattr(args, "path", ".")).resolve()
    if target_input.is_file():
        config_path = target_input
    else:
        config_path = target_input / ".entropy.yml"
        if not config_path.exists():
            config_path = target_input / ".entropy.yaml"

    if not config_path.exists():
        print(f"Error: Configuration file not found at '{config_path}'", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    try:
        content = config_path.read_text(encoding="utf-8")
        from app.core.project_config import parse_entropy_config

        cfg = parse_entropy_config(content, file_path=config_path)
        cfg_hash = cfg.compute_hash()
        if not getattr(args, "quiet", False):
            print(f"✓ Configuration is valid: {config_path.name}")
            print(f"  Project: {cfg.project.name}")
            print(f"  Hash:    {cfg_hash}")
        return EXIT_PASS
    except Exception as exc:
        print(f"❌ Configuration error in '{config_path}': {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR


def cmd_baseline_create(args: argparse.Namespace) -> int:
    """Scan repository and create .entropy-baseline.json."""
    target_path = Path(getattr(args, "path", ".")).resolve()
    if not target_path.exists():
        print(f"Error: Target path '{target_path}' does not exist.", file=sys.stderr)
        return EXIT_SYSTEM_ERROR

    from app.core.project_config import load_project_config

    try:
        cfg = load_project_config(target_path)
    except Exception as c_err:
        print(f"Configuration error: {c_err}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    baseline_filename = cfg.scoring.baseline_file if cfg else ".entropy-baseline.json"
    baseline_path = target_path / baseline_filename

    try:
        scan, findings = _run_single_scan_pipeline(repo_path=target_path)
        from app.core.baseline import EntropyBaseline, save_baseline_file

        active_f = [f for f in findings if not getattr(f, "is_suppressed", False)]
        baseline = EntropyBaseline.from_scan(
            scan=scan,
            project_name=cfg.project.name if cfg else None,
            project_id=cfg.project.id if cfg else None,
            config_hash=cfg.compute_hash() if cfg else None,
            active_findings=active_f,
        )
        save_baseline_file(baseline, baseline_path)
        if not getattr(args, "quiet", False):
            print(f"Baseline created at {baseline_path}")
            print(f"  Score:    {baseline.scan.score}/100 ({baseline.scan.band})")
            print(f"  Findings: {baseline.scan.total_findings}")
            if baseline.scan.commit_sha:
                print(f"  Commit:   {baseline.scan.commit_sha[:8]}")
        return EXIT_PASS
    except RepositoryError as exc:
        print(f"Baseline creation failed: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR
    except Exception as exc:
        print(f"Unexpected baseline error: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def cmd_baseline_show(args: argparse.Namespace) -> int:
    """Inspect established baseline."""
    target_path = Path(getattr(args, "path", ".")).resolve()
    from app.core.project_config import load_project_config

    try:
        cfg = load_project_config(target_path)
    except Exception as c_err:
        print(f"Configuration error: {c_err}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    baseline_filename = cfg.scoring.baseline_file if cfg else ".entropy-baseline.json"
    baseline_path = target_path / baseline_filename

    if not baseline_path.is_file():
        print(f"Error: Baseline file not found at '{baseline_path}'", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    try:
        from app.core.baseline import load_baseline_file

        baseline = load_baseline_file(baseline_path)
        fmt = getattr(args, "format", "text")
        if fmt == "json":
            print(baseline.to_json(indent=2))
        else:
            print("Entropy Baseline Summary:")
            print(f"  Project:        {baseline.project.name}")
            print(f"  Baseline Score: {baseline.scan.score}/100 ({baseline.scan.band})")
            print(f"  Findings:       {baseline.scan.total_findings}")
            print(f"  Created At:     {baseline.scan.created_at}")
            if baseline.scan.commit_sha:
                print(f"  Commit SHA:     {baseline.scan.commit_sha}")
            if baseline.scan.config_hash:
                print(f"  Config Hash:    {baseline.scan.config_hash}")
        return EXIT_PASS
    except Exception as exc:
        print(f"Error loading baseline: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR


def cmd_baseline_update(args: argparse.Namespace) -> int:
    """Rescan repository and update .entropy-baseline.json."""
    return cmd_baseline_create(args)


def cmd_baseline_clear(args: argparse.Namespace) -> int:
    """Clear/delete the baseline file."""
    target_path = Path(getattr(args, "path", ".")).resolve()
    from app.core.project_config import load_project_config

    try:
        cfg = load_project_config(target_path)
    except Exception as c_err:
        print(f"Configuration error: {c_err}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    baseline_filename = cfg.scoring.baseline_file if cfg else ".entropy-baseline.json"
    baseline_path = target_path / baseline_filename

    if not getattr(args, "yes", False):
        print("Error: Use --yes to confirm deletion of baseline file.", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    if not baseline_path.is_file():
        print(f"Notice: Baseline file '{baseline_path}' does not exist.", file=sys.stderr)
        return EXIT_PASS

    try:
        baseline_path.unlink()
        if not getattr(args, "quiet", False):
            print(f"Removed baseline file: {baseline_path}")
        return EXIT_PASS
    except Exception as exc:
        print(f"Error removing baseline file: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


def cmd_policy_validate(args: argparse.Namespace) -> int:
    """Validate policy configuration file."""
    path = Path(args.policy_file)
    if not path.is_file():
        print(f"Error: Policy file not found: {path}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    try:
        policy = parse_policy_file(path)
        print(f"✓ Policy configuration '{path}' is VALID.")
        print(f"  Name: {policy.name}")
        print(f"  Version: {policy.version}")
        print(f"  Description: {policy.description}")
        return EXIT_PASS
    except PolicyConfigurationError as exc:
        print(f"❌ Policy validation failed for '{path}':", file=sys.stderr)
        print(f"  {exc.message}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    except Exception as exc:
        print(f"❌ Unexpected error reading policy file: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR


def cmd_policy_evaluate(args: argparse.Namespace) -> int:
    """Evaluate scan or comparison against policy."""
    # 1. Load Policy
    policy: PolicyConfig
    if args.policy:
        try:
            policy = parse_policy_file(args.policy)
        except PolicyConfigurationError as exc:
            print(f"Error in policy file: {exc.message}", file=sys.stderr)
            return EXIT_CONFIG_ERROR
    else:
        policy = get_default_policy()

    # 2. Load Target Data
    evaluation: PolicyEvaluation
    try:
        if args.comparison_file:
            path = Path(args.comparison_file)
            if not path.is_file():
                print(f"Comparison file not found: {path}", file=sys.stderr)
                return EXIT_SYSTEM_ERROR
            comp = ScanComparisonResult.model_validate_json(path.read_text(encoding="utf-8"))
            evaluation = PolicyEvaluator.evaluate(policy=policy, comparison=comp)

        elif args.scan_file:
            path = Path(args.scan_file)
            if not path.is_file():
                print(f"Scan file not found: {path}", file=sys.stderr)
                return EXIT_SYSTEM_ERROR
            scan = RepositoryScanResult.model_validate_json(path.read_text(encoding="utf-8"))
            evaluation = PolicyEvaluator.evaluate(policy=policy, current_scan=scan)

        elif args.base_scan_id and args.head_scan_id:
            evaluation = policy_service.evaluate_comparison(
                current_scan_id=args.head_scan_id,
                previous_scan_id=args.base_scan_id,
                policy=policy,
            )

        elif args.scan_id:
            evaluation = policy_service.evaluate_scan(scan_id=args.scan_id, policy=policy)

        elif args.comparison_id:
            evaluation = policy_service.evaluate_pr_analysis(
                analysis_id=args.comparison_id,
                policy=policy,
            )

        else:
            print(
                "Error: One of --scan-id, --scan-file, --comparison-file, or "
                "(--base-scan-id AND --head-scan-id) must be specified.",
                file=sys.stderr,
            )
            return EXIT_CONFIG_ERROR

    except ValueError as exc:
        print(f"Analysis data error: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR
    except Exception as exc:
        print(f"Unexpected evaluation error: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR

    # 3. Output
    if getattr(args, "json", False) or getattr(args, "format", "text") == "json":
        print(evaluation.model_dump_json(indent=2))
    else:
        print(format_evaluation_text(evaluation))

    # 4. Exit Code Calculation
    if evaluation.status == PolicyStatus.FAIL:
        return EXIT_POLICY_FAIL
    elif evaluation.status == PolicyStatus.WARN and getattr(args, "fail_on_warn", False):
        return EXIT_POLICY_FAIL
    else:
        return EXIT_PASS


# -----------------------------------------------------------------------------
# ARGUMENT PARSER
# -----------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser for Entropy CLI."""
    parser = argparse.ArgumentParser(
        prog="entropy",
        description="Entropy: Deterministic Architectural & Security Debt Engine",
    )

    # Top-level version flag
    parser.add_argument(
        "--version",
        action="version",
        version=f"entropy {settings.VERSION}",
        help="Show program's version number and exit",
    )

    # Global options
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in output",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress informational output, displaying only results or errors",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose diagnostic output",
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 1. scan <path>
    scan_parser = subparsers.add_parser("scan", help="Scan a repository, compute findings and score")
    scan_parser.add_argument("path", default=".", nargs="?", help="Path to repository directory (default: current directory)")
    scan_parser.add_argument("--format", choices=["text", "json", "sarif"], default="text", help="Output format (default: text)")

    # 2. check <path>
    check_parser = subparsers.add_parser("check", help="Scan repository and evaluate against policy (primary CI gate)")
    check_parser.add_argument("path", default=".", nargs="?", help="Path to repository directory (default: current directory)")
    check_parser.add_argument("--policy", "-p", help="Path to custom policy file (default: built-in policy)")
    check_parser.add_argument("--fail-on-warn", action="store_true", help="Treat policy warnings as failures (exit 1)")
    check_parser.add_argument("--format", choices=["text", "json", "sarif"], default="text", help="Output format (default: text)")

    # 3. findings <path>
    findings_parser = subparsers.add_parser("findings", help="Inspect detailed findings for a repository")
    findings_parser.add_argument("path", default=".", nargs="?", help="Path to repository directory (default: current directory)")
    findings_parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], help="Filter by severity")
    findings_parser.add_argument("--category", help="Filter by debt category")
    findings_parser.add_argument("--rule", help="Filter by specific rule ID (e.g. ENT-ERR-001)")
    findings_parser.add_argument("--file", help="Filter by file path substring")
    findings_parser.add_argument("--new", action="store_true", help="Show only findings introduced since baseline")
    findings_parser.add_argument("--suppressed", action="store_true", help="Show only suppressed findings")
    findings_parser.add_argument("--format", choices=["text", "json", "sarif"], default="text", help="Output format (default: text)")

    # 4. compare <base> <head>
    compare_parser = subparsers.add_parser("compare", help="Compare debt between two repository scans or paths")
    compare_parser.add_argument("base", help="Base repository directory path or base scan ID")
    compare_parser.add_argument("head", help="Head repository directory path or head scan ID")
    compare_parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format (default: text)")

    # 5. explain <finding-id>
    explain_parser = subparsers.add_parser("explain", help="Get advisory AI explanation and remediation for a finding")
    explain_parser.add_argument("finding_id", help="Deterministic finding ID to explain")
    explain_parser.add_argument("--scan-id", help="Optional scan ID where finding was observed")

    # 6. version
    subparsers.add_parser("version", help="Display Entropy engine version")

    # 7. init <path>
    init_parser = subparsers.add_parser("init", help="Initialize a minimal .entropy.yml configuration file")
    init_parser.add_argument("path", default=".", nargs="?", help="Target repository directory (default: current directory)")

    # 8. config group
    config_parser = subparsers.add_parser("config", help="Project configuration file management")
    config_subparsers = config_parser.add_subparsers(dest="config_action", help="Configuration actions")
    cfg_val_parser = config_subparsers.add_parser("validate", help="Validate .entropy.yml configuration file")
    cfg_val_parser.add_argument("path", default=".", nargs="?", help="Target repository directory or config file (default: current directory)")

    # 9. baseline group
    baseline_parser = subparsers.add_parser("baseline", help="Baseline creation and inspection")
    baseline_subparsers = baseline_parser.add_subparsers(dest="baseline_action", help="Baseline actions")

    b_create_parser = baseline_subparsers.add_parser("create", help="Create baseline file from repository scan")
    b_create_parser.add_argument("path", default=".", nargs="?", help="Path to repository directory (default: current directory)")

    b_show_parser = baseline_subparsers.add_parser("show", help="Show established baseline metadata")
    b_show_parser.add_argument("path", default=".", nargs="?", help="Path to repository directory (default: current directory)")
    b_show_parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format (default: text)")

    b_update_parser = baseline_subparsers.add_parser("update", help="Rescan repository and update baseline file")
    b_update_parser.add_argument("path", default=".", nargs="?", help="Path to repository directory (default: current directory)")

    b_clear_parser = baseline_subparsers.add_parser("clear", help="Delete baseline file")
    b_clear_parser.add_argument("path", default=".", nargs="?", help="Path to repository directory (default: current directory)")
    b_clear_parser.add_argument("--yes", action="store_true", help="Confirm deletion of baseline file")

    # 10. policy group
    policy_parser = subparsers.add_parser("policy", help="Policy engine management and evaluation")
    policy_subparsers = policy_parser.add_subparsers(dest="policy_action", help="Policy actions")

    val_parser = policy_subparsers.add_parser("validate", help="Validate a policy file")
    val_parser.add_argument("policy_file", help="Path to policy YAML or JSON file")

    eval_parser = policy_subparsers.add_parser("evaluate", help="Evaluate debt policy")
    eval_parser.add_argument("--policy", "-p", help="Path to custom policy file")
    eval_parser.add_argument("--scan-id", help="Scan ID from database")
    eval_parser.add_argument("--scan-file", help="Path to exported scan JSON file")
    eval_parser.add_argument("--base-scan-id", help="Base scan ID for differential evaluation")
    eval_parser.add_argument("--head-scan-id", help="Head scan ID for differential evaluation")
    eval_parser.add_argument("--comparison-id", help="PR analysis / comparison ID")
    eval_parser.add_argument("--comparison-file", help="Path to exported ScanComparisonResult JSON")
    eval_parser.add_argument("--fail-on-warn", action="store_true", help="Treat warnings as failure (exit 1)")
    eval_parser.add_argument("--json", action="store_true", help="Output raw JSON instead of text")

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "verbose", False):
        logging.basicConfig(level=logging.DEBUG)

    if args.subcommand == "scan":
        return cmd_scan(args)
    elif args.subcommand == "check":
        return cmd_check(args)
    elif args.subcommand == "findings":
        return cmd_findings(args)
    elif args.subcommand == "compare":
        return cmd_compare(args)
    elif args.subcommand == "explain":
        return cmd_explain(args)
    elif args.subcommand == "version":
        return cmd_version(args)
    elif args.subcommand == "init":
        return cmd_init(args)
    elif args.subcommand == "config":
        if args.config_action == "validate":
            return cmd_config_validate(args)
        else:
            parser.parse_args(["config", "--help"])
            return EXIT_CONFIG_ERROR
    elif args.subcommand == "baseline":
        if args.baseline_action == "create":
            return cmd_baseline_create(args)
        elif args.baseline_action == "show":
            return cmd_baseline_show(args)
        elif args.baseline_action == "update":
            return cmd_baseline_update(args)
        elif args.baseline_action == "clear":
            return cmd_baseline_clear(args)
        else:
            parser.parse_args(["baseline", "--help"])
            return EXIT_CONFIG_ERROR
    elif args.subcommand == "policy":
        if args.policy_action == "validate":
            return cmd_policy_validate(args)
        elif args.policy_action == "evaluate":
            return cmd_policy_evaluate(args)
        else:
            parser.parse_args(["policy", "--help"])
            return EXIT_CONFIG_ERROR

    parser.print_help()
    return EXIT_CONFIG_ERROR


if __name__ == "__main__":
    sys.exit(main())

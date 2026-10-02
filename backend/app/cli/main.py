"""Entropy Command-Line Interface.

Provides deterministic CLI tools for CI/CD gates, local policy evaluation,
and configuration validation.

Exit Codes:
  0 = PASS (or WARN when --fail-on-warn is omitted)
  1 = POLICY FAIL (or WARN when --fail-on-warn is provided)
  2 = CONFIGURATION / ARGUMENT / VALIDATION ERROR
  3 = ANALYSIS / SYSTEM / DATA NOT FOUND ERROR
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.comparison.models import ScanComparisonResult
from app.models.domain.scan import RepositoryScanResult
from app.policy.evaluator import PolicyEvaluator
from app.policy.models import PolicyConfig, PolicyEvaluation, PolicyStatus
from app.policy.parser import PolicyConfigurationError, get_default_policy, parse_policy_file
from app.policy.service import policy_service

EXIT_PASS = 0
EXIT_POLICY_FAIL = 1
EXIT_CONFIG_ERROR = 2
EXIT_SYSTEM_ERROR = 3


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
    if getattr(args, "json", False):
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


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser for Entropy CLI."""
    parser = argparse.ArgumentParser(
        prog="entropy",
        description="Entropy: Deterministic Architectural & Security Debt Engine",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # Policy command group
    policy_parser = subparsers.add_parser("policy", help="Policy engine management and evaluation")
    policy_subparsers = policy_parser.add_subparsers(dest="policy_action", help="Policy actions")

    # policy validate <file>
    val_parser = policy_subparsers.add_parser("validate", help="Validate a policy file")
    val_parser.add_argument("policy_file", help="Path to policy YAML or JSON file")

    # policy evaluate ...
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

    if args.subcommand == "policy":
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

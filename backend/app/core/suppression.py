"""Suppression models and AST / inline comment parsing for Entropy findings."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from app.models.domain.finding import Finding


class SuppressionSource(StrEnum):
    """Source provenance of a finding suppression."""

    CONFIG_RULE = "config_rule"
    CONFIG_FINDING = "config_finding"
    INLINE = "inline"


@dataclass
class InlineSuppression:
    """Inline comment suppression parsed from source file."""

    file_path: str
    line_number: int
    rule_ids: list[str]


# Pattern for inline suppression: # entropy: ignore[RULE-1, RULE-2] or // entropy: ignore[...]
INLINE_SUPPRESSION_REGEX = re.compile(
    r"(?:#|//|/\*)\s*entropy:\s*ignore\[([A-Za-z0-9_,\s-]+)\]",
    re.IGNORECASE,
)


def get_valid_rule_ids() -> set[str]:
    """Return all valid uppercase rule IDs across all registered analyzers."""
    from app.analyzers.registry import default_registry

    return {r.rule_id.upper() for r in default_registry.list_rules()}


def extract_inline_suppressions(
    source_code: str,
    relative_path: str,
    valid_rules: set[str] | None = None,
) -> list[InlineSuppression]:
    """Safely extract inline suppressions from Python source code without executing it.

    Validates that specified rule IDs are recognized if valid_rules set is provided.
    """
    suppressions: list[InlineSuppression] = []
    lines = source_code.splitlines()

    for idx, line in enumerate(lines, start=1):
        match = INLINE_SUPPRESSION_REGEX.search(line)
        if match:
            raw_rules = match.group(1)
            rule_tokens = [r.strip().upper() for r in raw_rules.split(",") if r.strip()]
            for r in rule_tokens:
                if valid_rules is not None and r not in valid_rules:
                    raise ValueError(
                        f"Unknown rule ID '{r}' in inline suppression at {relative_path}:{idx}. "
                        "Specify a valid Entropy rule ID."
                    )
            if rule_tokens:
                suppressions.append(
                    InlineSuppression(
                        file_path=relative_path,
                        line_number=idx,
                        rule_ids=rule_tokens,
                    )
                )

    return suppressions


def apply_suppressions(
    findings: list[Finding],
    suppressed_rules: set[str] | None = None,
    suppressed_finding_ids: set[str] | None = None,
    inline_suppressions: list[InlineSuppression] | None = None,
) -> tuple[list[Finding], list[Finding]]:
    """Partition findings into (active_findings, suppressed_findings) deterministically.

    Suppressed findings retain full finding metadata and record suppression provenance.
    """
    rules_set = {r.upper() for r in (suppressed_rules or set())}
    ids_set = set(suppressed_finding_ids or set())

    # Map of (file_path, line_number) -> set of rule_ids
    inline_map: dict[tuple[str, int], set[str]] = {}
    for item in inline_suppressions or []:
        norm_file = item.file_path.replace("\\", "/")
        key = (norm_file, item.line_number)
        inline_map.setdefault(key, set()).update(item.rule_ids)

    active: list[Finding] = []
    suppressed: list[Finding] = []

    for f in findings:
        norm_file = f.file.replace("\\", "/")
        is_suppressed = False
        source: SuppressionSource | None = None
        reason = ""

        # 1. Config rule-level suppression
        if f.rule_id.upper() in rules_set:
            is_suppressed = True
            source = SuppressionSource.CONFIG_RULE
            reason = f"Suppressed by project configuration rule filter ({f.rule_id})"

        # 2. Config finding-level suppression (id or fingerprint)
        elif f.id in ids_set or f.fingerprint in ids_set:
            is_suppressed = True
            source = SuppressionSource.CONFIG_FINDING
            reason = f"Suppressed by project configuration finding identifier ({f.id})"

        # 3. Inline suppression: checks line_start, line_end, or preceding line
        else:
            for lno in range(max(1, f.line_start - 1), f.line_end + 1):
                inline_rules = inline_map.get((norm_file, lno), set())
                if f.rule_id.upper() in inline_rules:
                    is_suppressed = True
                    source = SuppressionSource.INLINE
                    reason = f"Suppressed by inline source comment at line {lno}"
                    break

        if is_suppressed and source is not None:
            f.is_suppressed = True
            f.suppression_source = source.value
            f.suppression_reason = reason
            f.status = "suppressed"
            suppressed.append(f)
        else:
            f.is_suppressed = False
            f.suppression_source = None
            f.suppression_reason = None
            active.append(f)

    return active, suppressed

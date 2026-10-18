"""Suppression models and AST / inline comment parsing for Entropy findings."""

from __future__ import annotations

import io
import logging
import re
import tokenize
from dataclasses import dataclass
from enum import StrEnum

from app.models.domain.finding import Finding

logger = logging.getLogger("entropy.suppression")


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


# Pattern for inline suppression directive
INLINE_SUPPRESSION_REGEX = re.compile(
    r"^#[ \t]*entropy:[ \t]*ignore\[([A-Za-z0-9_,\s-]+)\]",
    re.IGNORECASE,
)

JSTS_INLINE_SUPPRESSION_REGEX = re.compile(
    r"^(?://|/\*)[ \t]*entropy:[ \t]*ignore\[([A-Za-z0-9_,\s-]+)\]",
    re.IGNORECASE,
)


def get_valid_rule_ids() -> set[str]:
    """Return all valid uppercase rule IDs across all registered analyzers."""
    from app.analyzers.registry import default_registry

    return {r.rule_id.upper() for r in default_registry.list_rules()}


def _extract_python_suppressions(source_code: str) -> list[tuple[int, str]]:
    """Extract suppression directives from Python comments using tokenize (ignoring docstrings and explanatory text)."""
    results: list[tuple[int, str]] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source_code).readline)
        for tok in tokens:
            if tok.type == tokenize.COMMENT:
                match = INLINE_SUPPRESSION_REGEX.match(tok.string.strip())
                if match:
                    results.append((tok.start[0], match.group(1)))
    except Exception:
        # Fallback to line scanning if tokenize fails
        for idx, line in enumerate(source_code.splitlines(), start=1):
            hash_idx = line.find("#")
            if hash_idx != -1:
                comment_part = line[hash_idx:].strip()
                match = INLINE_SUPPRESSION_REGEX.match(comment_part)
                if match:
                    results.append((idx, match.group(1)))
    return results


def _extract_jsts_suppressions(source_code: str) -> list[tuple[int, str]]:
    """Extract suppression directives from JS/TS source code."""
    results: list[tuple[int, str]] = []
    lines = source_code.splitlines()
    in_block_comment = False

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if in_block_comment:
            if "*/" in stripped:
                in_block_comment = False
            continue

        # Check for start of block comment that is a suppression
        if stripped.startswith("/*"):
            match = JSTS_INLINE_SUPPRESSION_REGEX.match(stripped)
            if match:
                results.append((idx, match.group(1)))
            if "*/" not in stripped:
                in_block_comment = True
            continue

        # Check single-line comment //
        slash_idx = line.find("//")
        if slash_idx != -1:
            comment_part = line[slash_idx:].strip()
            match = JSTS_INLINE_SUPPRESSION_REGEX.match(comment_part)
            if match:
                results.append((idx, match.group(1)))
    return results


def extract_inline_suppressions(
    source_code: str,
    relative_path: str,
    valid_rules: set[str] | None = None,
) -> list[InlineSuppression]:
    """Safely extract inline suppressions from source code without executing it.

    Filters out unknown rule IDs with a warning so that one bad suppression
    does NOT abort processing of other valid suppressions.
    """
    suppressions: list[InlineSuppression] = []
    ext = relative_path.lower().rsplit(".", 1)[-1] if "." in relative_path else ""

    if ext in ("js", "jsx", "ts", "tsx", "mjs", "cjs"):
        raw_suppressions = _extract_jsts_suppressions(source_code)
    else:
        raw_suppressions = _extract_python_suppressions(source_code)

    for line_num, raw_rules in raw_suppressions:
        rule_tokens = [r.strip().upper() for r in raw_rules.split(",") if r.strip()]
        valid_tokens: list[str] = []
        for r in rule_tokens:
            if valid_rules is not None and r not in valid_rules:
                logger.warning(
                    "Unknown rule ID '%s' in inline suppression at %s:%d. Ignoring invalid rule.",
                    r,
                    relative_path,
                    line_num,
                )
            else:
                valid_tokens.append(r)
        if valid_tokens:
            suppressions.append(
                InlineSuppression(
                    file_path=relative_path,
                    line_number=line_num,
                    rule_ids=valid_tokens,
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

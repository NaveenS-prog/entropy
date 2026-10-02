"""Rule definitions and finding generators for Code Duplication & Boilerplate Debt."""

from __future__ import annotations

import hashlib
from typing import Any

from app.analyzers.duplication.models import BoilerplatePattern, DuplicationCluster
from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.models.domain.finding import CodeEvidence, Finding
from app.models.domain.rule import RuleDefinition

RULE_ENT_DUP_001 = RuleDefinition(
    rule_id="ENT-DUP-001",
    category=DebtCategory.CODE_DUPLICATION,
    title="Exact Structural Duplication",
    description=(
        "Detects two or more functions or code blocks that share identical normalized "
        "AST structure despite differing variable names, comments, docstrings, or formatting."
    ),
    default_severity=Severity.LOW,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.PYTHON],
    impact_template=(
        "Identical logic duplicated across locations creates maintenance friction, "
        "as bug fixes or architectural refactors must be manually synchronized."
    ),
    recommendation_template=(
        "Extract the shared implementation into a centralized, reusable utility or service function."
    ),
    rationale=(
        "Duplicated structural logic is maintenance debt that increases the likelihood of "
        "divergent bug fixes and accidental security regressions."
    ),
)

RULE_ENT_DUP_002 = RuleDefinition(
    rule_id="ENT-DUP-002",
    category=DebtCategory.CODE_DUPLICATION,
    title="Highly Similar Function Implementation",
    description=(
        "Detects functions with high structural similarity (>= 80%) where control flow, "
        "AST structure, and operation sequence are substantially identical."
    ),
    default_severity=Severity.LOW,
    default_confidence=Confidence.MEDIUM,
    languages=[SupportedLanguage.PYTHON],
    impact_template=(
        "Functions implementing nearly identical logic with slight parameterization increase "
        "cognitive load and codebase entropy."
    ),
    recommendation_template=(
        "Parameterize or generalize the common structural pattern into a single shared helper."
    ),
    rationale=(
        "Near-identical functions are often created by copy-pasting existing routines, "
        "leading to duplicated maintenance costs."
    ),
)

RULE_ENT_DUP_003 = RuleDefinition(
    rule_id="ENT-DUP-003",
    category=DebtCategory.CODE_DUPLICATION,
    title="Repeated Boilerplate Pattern",
    description=(
        "Detects repeated structural boilerplate (e.g. repeated error handling wrappers, "
        "repetitive validation routines) recurring across 3 or more locations."
    ),
    default_severity=Severity.LOW,
    default_confidence=Confidence.MEDIUM,
    languages=[SupportedLanguage.PYTHON],
    impact_template=(
        "Repetitive boilerplate patterns clutter core business logic and make universal updates cumbersome."
    ),
    recommendation_template=(
        "Encapsulate recurring boilerplate into a reusable decorator, context manager, or middleware."
    ),
    rationale=(
        "Boilerplate code repetition obscures business logic and encourages copy-paste programming habits."
    ),
)

RULE_ENT_DUP_004 = RuleDefinition(
    rule_id="ENT-DUP-004",
    category=DebtCategory.CODE_DUPLICATION,
    title="Cross-File Structural Duplication",
    description=(
        "Detects substantial structural duplication spanning multiple files or modules, "
        "indicating architectural coupling and lack of domain sharing."
    ),
    default_severity=Severity.MEDIUM,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.PYTHON],
    impact_template=(
        "Duplication crossing file boundaries creates hidden architectural coupling between distinct modules."
    ),
    recommendation_template=(
        "Move the duplicated implementation into a shared common/core module accessible by both components."
    ),
    rationale=(
        "Cross-file duplication indicates architectural fragmentation where modules re-implement common capabilities."
    ),
)

RULE_ENT_DUP_005 = RuleDefinition(
    rule_id="ENT-DUP-005",
    category=DebtCategory.CODE_DUPLICATION,
    title="Structural Duplication Cluster",
    description=(
        "Detects a cluster of 3 or more structurally similar functions, representing "
        "a widespread maintenance bottleneck."
    ),
    default_severity=Severity.MEDIUM,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.PYTHON],
    impact_template=(
        "A large duplication cluster multiplies maintenance debt; any change to the underlying "
        "behavior requires updating every scattered instance."
    ),
    recommendation_template=(
        "Refactor the duplicated cluster into a unified strategy or shared abstraction."
    ),
    rationale=(
        "Clusters of 3+ duplicates accumulate high debt velocity and risk inconsistent behavior under modification."
    ),
)

ALL_DUPLICATION_RULES = [
    RULE_ENT_DUP_001,
    RULE_ENT_DUP_002,
    RULE_ENT_DUP_003,
    RULE_ENT_DUP_004,
    RULE_ENT_DUP_005,
]


def create_finding_for_cluster(cluster: DuplicationCluster) -> Finding:
    """Generate a deterministic Finding object representing a duplication cluster."""
    rep = cluster.representative

    # Select appropriate rule based on cluster properties
    if cluster.occurrence_count >= 3:
        rule = RULE_ENT_DUP_005
        # Higher severity if widespread across 4+ files or 5+ occurrences
        severity = Severity.HIGH if (len(cluster.files) >= 4 or cluster.occurrence_count >= 5) else Severity.MEDIUM
        confidence = Confidence.HIGH
        title = (
            f"Duplication Cluster: {cluster.occurrence_count} Similar Functions "
            f"Across {len(cluster.files)} File(s)"
        )
    elif cluster.is_cross_file:
        rule = RULE_ENT_DUP_004
        severity = Severity.MEDIUM
        confidence = Confidence.HIGH if cluster.is_exact else Confidence.MEDIUM
        title = (
            f"Cross-File Structural Duplication in '{rep.name}' "
            f"({int(cluster.similarity * 100)}% Match across {len(cluster.files)} Files)"
        )
    else:
        if cluster.is_exact:
            rule = RULE_ENT_DUP_001
            severity = Severity.LOW
            confidence = Confidence.HIGH
            title = f"Exact Structural Duplication in '{rep.name}' (100% Normalized Match)"
        else:
            rule = RULE_ENT_DUP_002
            severity = Severity.LOW
            confidence = Confidence.MEDIUM
            title = (
                f"Highly Similar Function Implementation in '{rep.name}' "
                f"({int(cluster.similarity * 100)}% Structural Match)"
            )

    # Format member locations
    member_locations_str = "\n".join(
        f"  - {m.file_path}:{m.location.line_start} (symbol: `{m.name}`)"
        for m in cluster.members
    )

    description = (
        f"{rule.description}\n\n"
        f"Cluster Details:\n"
        f"- Structural Similarity: {int(cluster.similarity * 100)}%\n"
        f"- Occurrences: {cluster.occurrence_count}\n"
        f"- Files Affected: {len(cluster.files)}\n"
        f"- Normalized AST Size: {cluster.normalized_size} nodes\n\n"
        f"Duplicate Locations:\n{member_locations_str}"
    )

    evidence = CodeEvidence(
        content=rep.source_code,
        line_start=rep.location.line_start,
        line_end=rep.location.line_end,
        highlight_lines=list(range(rep.location.line_start, rep.location.line_end + 1)),
    )

    # Deterministic finding ID and fingerprint
    all_members_key = ",".join(m.id for m in cluster.members)
    sig_raw = f"{rule.rule_id}:{cluster.cluster_id}:{all_members_key}"
    finding_id = hashlib.sha256(sig_raw.encode("utf-8")).hexdigest()[:16]
    fingerprint = hashlib.sha256(f"{rule.rule_id}:{rep.file_path}:{rep.name}:{cluster.cluster_id}".encode()).hexdigest()[:16]

    metadata: dict[str, Any] = {
        "cluster_id": cluster.cluster_id,
        "similarity": cluster.similarity,
        "is_exact": cluster.is_exact,
        "is_cross_file": cluster.is_cross_file,
        "occurrences": cluster.occurrence_count,
        "affected_files": sorted(cluster.files),
        "duplicate_locations": [
            {
                "file": m.file_path,
                "line_start": m.location.line_start,
                "line_end": m.location.line_end,
                "name": m.name,
            }
            for m in cluster.members
        ],
        "normalized_size_nodes": cluster.normalized_size,
    }

    return Finding(
        id=finding_id,
        category=DebtCategory.CODE_DUPLICATION,
        rule_id=rule.rule_id,
        severity=severity,
        confidence=confidence,
        file=rep.file_path,
        line_start=rep.location.line_start,
        line_end=rep.location.line_end,
        column_start=rep.location.col_offset,
        column_end=rep.location.end_col_offset,
        symbol=rep.name,
        title=title,
        description=description,
        evidence=evidence,
        impact=rule.impact_template,
        recommendation=rule.recommendation_template,
        fingerprint=fingerprint,
        metadata=metadata,
    )


def create_finding_for_boilerplate(bp: BoilerplatePattern) -> Finding:
    """Generate a deterministic Finding for repeated structural boilerplate."""
    rule = RULE_ENT_DUP_003
    rep = bp.representative

    locations_str = "\n".join(
        f"  - {m.file_path}:{loc.line_start} (symbol: `{m.name}`)"
        for m, loc in bp.occurrences
    )

    description = (
        f"{rule.description}\n\n"
        f"Pattern: {bp.pattern_type}\n"
        f"Repeated Occurrences: {bp.frequency} across {len(bp.files)} files.\n\n"
        f"Affected Locations:\n{locations_str}"
    )

    evidence = CodeEvidence(
        content=rep.source_code,
        line_start=rep.location.line_start,
        line_end=rep.location.line_end,
        highlight_lines=list(range(rep.location.line_start, rep.location.line_end + 1)),
    )

    sig_raw = f"{rule.rule_id}:{bp.pattern_id}"
    finding_id = hashlib.sha256(sig_raw.encode("utf-8")).hexdigest()[:16]
    fingerprint = hashlib.sha256(f"{rule.rule_id}:{rep.file_path}:{bp.pattern_id}".encode()).hexdigest()[:16]

    metadata: dict[str, Any] = {
        "pattern_id": bp.pattern_id,
        "pattern_type": bp.pattern_type,
        "frequency": bp.frequency,
        "affected_files": sorted(bp.files),
        "occurrences": [
            {
                "file": m.file_path,
                "line_start": loc.line_start,
                "line_end": loc.line_end,
                "name": m.name,
            }
            for m, loc in bp.occurrences
        ],
    }

    return Finding(
        id=finding_id,
        category=DebtCategory.CODE_DUPLICATION,
        rule_id=rule.rule_id,
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        file=rep.file_path,
        line_start=rep.location.line_start,
        line_end=rep.location.line_end,
        column_start=rep.location.col_offset,
        column_end=rep.location.end_col_offset,
        symbol=rep.name,
        title=f"Repeated Boilerplate Pattern Across {bp.frequency} Functions",
        description=description,
        evidence=evidence,
        impact=rule.impact_template,
        recommendation=rule.recommendation_template,
        fingerprint=fingerprint,
        metadata=metadata,
    )

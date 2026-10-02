"""Rule definitions and finding generators for Phase 9 Architectural Consistency Debt."""

from __future__ import annotations

import hashlib

from app.analyzers.architecture.models import (
    ArchitecturalLayer,
    ArchitecturalResponsibility,
    DependencyCycle,
    ModuleNode,
)
from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.models.domain.finding import CodeEvidence, Finding
from app.models.domain.rule import RuleDefinition

RULE_ENT_ARCH_001 = RuleDefinition(
    rule_id="ENT-ARCH-001",
    category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
    title="Circular Module Dependency",
    description=(
        "Detects statically observable circular import dependencies between local modules, "
        "causing tight coupling, import-order fragility, and difficult refactoring."
    ),
    default_severity=Severity.MEDIUM,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.PYTHON],
    impact_template=(
        "Circular dependencies make components tightly coupled, complicate unit testing in isolation, "
        "and can cause subtle runtime ImportError or initialization race conditions."
    ),
    recommendation_template=(
        "Break the circular dependency by extracting the shared interfaces, types, or utilities "
        "into a common lower-level module, or adopt dependency inversion."
    ),
    rationale=(
        "Clean software architectures maintain a directed acyclic graph (DAG) of dependencies. "
        "Cycles are structural architectural debt that increase system entropy."
    ),
)

RULE_ENT_ARCH_002 = RuleDefinition(
    rule_id="ENT-ARCH-002",
    category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
    title="Architectural Layer Boundary Violation",
    description=(
        "Detects components bypassing intermediate architectural layers (e.g. an API endpoint "
        "directly querying the database or repository internals) when the repository exhibits "
        "an established convention of delegating to a service layer."
    ),
    default_severity=Severity.MEDIUM,
    default_confidence=Confidence.MEDIUM,
    languages=[SupportedLanguage.PYTHON],
    impact_template=(
        "Bypassing architectural layers creates inconsistent abstractions, leaks database details into "
        "the presentation layer, and makes global transaction or caching policies difficult to maintain."
    ),
    recommendation_template=(
        "Delegate data access operations through the established domain/service layer instead of "
        "directly referencing persistence models and database sessions."
    ),
    rationale=(
        "Architectural consistency requires that comparable components follow the same layer boundaries."
    ),
)

RULE_ENT_ARCH_003 = RuleDefinition(
    rule_id="ENT-ARCH-003",
    category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
    title="Inconsistent Dependency Pattern",
    description=(
        "Detects components within the same module or group that obtain or instantiate the same "
        "dependency in conflicting ways (e.g. some endpoints use framework dependency injection "
        "while others manually construct the dependency)."
    ),
    default_severity=Severity.LOW,
    default_confidence=Confidence.MEDIUM,
    languages=[SupportedLanguage.PYTHON],
    impact_template=(
        "Inconsistent dependency acquisition hinders testing, bypasses framework lifecycle management, "
        "and creates unpredictable resource cleanup behavior."
    ),
    recommendation_template=(
        "Standardize on the established dependency-injection pattern across all endpoints in the group."
    ),
    rationale=(
        "Divergent dependency creation inside the same subsystem is a classic symptom of maintenance drift."
    ),
)

RULE_ENT_ARCH_004 = RuleDefinition(
    rule_id="ENT-ARCH-004",
    category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
    title="Inconsistent Configuration Access",
    description=(
        "Detects ad-hoc direct environment access (os.environ / os.getenv) in domain or API modules "
        "when the repository already maintains a centralized configuration/settings module."
    ),
    default_severity=Severity.LOW,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.PYTHON],
    impact_template=(
        "Scattering environment variable lookups throughout business logic bypasses type validation, "
        "default value fallbacks, and centralized configuration observability."
    ),
    recommendation_template=(
        "Import configuration attributes from the centralized settings module instead of calling "
        "os.environ or os.getenv directly in application components."
    ),
    rationale=(
        "Centralized configuration maintains single source of truth for runtime variables."
    ),
)

RULE_ENT_ARCH_005 = RuleDefinition(
    rule_id="ENT-ARCH-005",
    category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
    title="God Module / Excessively Responsible Module",
    description=(
        "Detects a module that concentrates an unusually high number of orthogonal architectural "
        "responsibilities (e.g. combining HTTP routing, database queries, authentication, and system I/O)."
    ),
    default_severity=Severity.HIGH,
    default_confidence=Confidence.MEDIUM,
    languages=[SupportedLanguage.PYTHON],
    impact_template=(
        "God modules become central points of failure, resist refactoring, and violate the Single "
        "Responsibility Principle by intermingling unrelated concerns."
    ),
    recommendation_template=(
        "Decompose the module into distinct, cohesive components separated by responsibility "
        "(e.g. routing handlers, domain services, persistence queries)."
    ),
    rationale=(
        "High responsibility concentration indicates severe architectural erosion."
    ),
)

RULE_ENT_ARCH_006 = RuleDefinition(
    rule_id="ENT-ARCH-006",
    category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
    title="God Class / Excessively Responsible Class",
    description=(
        "Detects an individual class with excessive method count that combines multiple unrelated "
        "architectural responsibilities (e.g. presentation, persistence, and business logic)."
    ),
    default_severity=Severity.MEDIUM,
    default_confidence=Confidence.MEDIUM,
    languages=[SupportedLanguage.PYTHON],
    impact_template=(
        "Massive classes with divergent concerns create high coupling, impede unit testing, and "
        "invite regressions during routine maintenance."
    ),
    recommendation_template=(
        "Refactor the class into smaller, cohesive classes using delegation or strategy patterns."
    ),
    rationale=(
        "Classes should encapsulate a single coherent responsibility."
    ),
)

RULE_ENT_ARCH_007 = RuleDefinition(
    rule_id="ENT-ARCH-007",
    category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
    title="Excessive Cross-Layer Coupling",
    description=(
        "Detects a module directly importing from 4 or more distinct architectural layers simultaneously, "
        "creating deep structural coupling across the system."
    ),
    default_severity=Severity.MEDIUM,
    default_confidence=Confidence.MEDIUM,
    languages=[SupportedLanguage.PYTHON],
    impact_template=(
        "Tight coupling across multiple disparate layers destroys architectural modularity and makes "
        "independent evolution of system tiers impossible."
    ),
    recommendation_template=(
        "Introduce intermediate service or facade abstractions to insulate the component from low-level tiers."
    ),
    rationale=(
        "Limiting fan-out across multiple layers maintains clear separation of concerns."
    ),
)

RULE_ENT_ARCH_008 = RuleDefinition(
    rule_id="ENT-ARCH-008",
    category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
    title="Inconsistent Architectural Pattern",
    description=(
        "Detects components within comparable functional groups that diverge from the dominant "
        "structural pattern established by peer components."
    ),
    default_severity=Severity.LOW,
    default_confidence=Confidence.MEDIUM,
    languages=[SupportedLanguage.PYTHON],
    impact_template=(
        "Divergent structural patterns in the same codebase increase cognitive load for engineers and "
        "prevent standardized cross-cutting operational concerns."
    ),
    recommendation_template=(
        "Align component implementation with the dominant architectural pattern established by peer modules."
    ),
    rationale=(
        "Architectural consistency across similar components ensures predictability and uniform maintenance."
    ),
)

ALL_ARCHITECTURE_RULES: list[RuleDefinition] = [
    RULE_ENT_ARCH_001,
    RULE_ENT_ARCH_002,
    RULE_ENT_ARCH_003,
    RULE_ENT_ARCH_004,
    RULE_ENT_ARCH_005,
    RULE_ENT_ARCH_006,
    RULE_ENT_ARCH_007,
    RULE_ENT_ARCH_008,
]


def create_circular_dependency_finding(
    cycle: DependencyCycle,
    primary_module: ModuleNode,
) -> Finding:
    """Generate ENT-ARCH-001 finding for a circular dependency."""
    rule = RULE_ENT_ARCH_001
    cycle_str = " -> ".join(cycle.cycle_path)
    description = (
        f"{rule.description}\n\n"
        f"Circular Dependency Path ({cycle.length} steps):\n"
        f"  {cycle_str}\n\n"
        f"Primary Module: `{primary_module.file_path}`"
    )

    # First import in primary module pointing to the cycle
    line_start = 1
    line_end = min(5, primary_module.loc)
    for imp in primary_module.imports:
        if imp.module in cycle.cycle_path or imp.name in cycle.cycle_path:
            line_start = imp.location.line_start
            line_end = imp.location.line_end
            break

    evidence_lines = primary_module.source_code.splitlines()
    snippet_content = "\n".join(evidence_lines[max(0, line_start - 1) : min(len(evidence_lines), line_end + 1)])
    evidence = CodeEvidence(
        content=snippet_content or f"# Import cycle: {cycle_str}",
        line_start=line_start,
        line_end=line_end,
        highlight_lines=[line_start],
    )

    sig_raw = f"{rule.rule_id}:{cycle.cycle_id}"
    finding_id = hashlib.sha256(sig_raw.encode("utf-8")).hexdigest()[:16]
    fingerprint = hashlib.sha256(f"{rule.rule_id}:{primary_module.file_path}:{cycle.cycle_id}".encode()).hexdigest()[:16]

    return Finding(
        id=finding_id,
        category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
        rule_id=rule.rule_id,
        severity=rule.default_severity,
        confidence=rule.default_confidence,
        file=primary_module.file_path,
        line_start=line_start,
        line_end=line_end,
        symbol=primary_module.module_name,
        title=f"Circular Module Dependency ({cycle.length} Modules in Cycle)",
        description=description,
        evidence=evidence,
        impact=rule.impact_template,
        recommendation=rule.recommendation_template,
        fingerprint=fingerprint,
        metadata={
            "cycle_path": cycle.cycle_path,
            "cycle_length": cycle.length,
            "cycle_id": cycle.cycle_id,
        },
    )


def create_layer_violation_finding(
    violating_mod: ModuleNode,
    target_mod: ModuleNode,
    expected_layer: str,
    line_start: int,
    line_end: int,
    snippet: str,
) -> Finding:
    """Generate ENT-ARCH-002 finding for architectural layer boundary violation."""
    rule = RULE_ENT_ARCH_002
    description = (
        f"{rule.description}\n\n"
        f"Violating Module: `{violating_mod.file_path}` (Layer: `{violating_mod.inferred_layer}`)\n"
        f"Bypassed Intermediate Layer: `{expected_layer}`\n"
        f"Target Direct Dependency: `{target_mod.file_path}` (Layer: `{target_mod.inferred_layer}`)"
    )

    evidence = CodeEvidence(
        content=snippet,
        line_start=line_start,
        line_end=line_end,
        highlight_lines=[line_start],
    )

    sig_raw = f"{rule.rule_id}:{violating_mod.file_path}:{target_mod.module_name}"
    finding_id = hashlib.sha256(sig_raw.encode("utf-8")).hexdigest()[:16]
    fingerprint = hashlib.sha256(f"{rule.rule_id}:{violating_mod.file_path}:{line_start}".encode()).hexdigest()[:16]

    return Finding(
        id=finding_id,
        category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
        rule_id=rule.rule_id,
        severity=rule.default_severity,
        confidence=rule.default_confidence,
        file=violating_mod.file_path,
        line_start=line_start,
        line_end=line_end,
        symbol=violating_mod.module_name,
        title=f"Architectural Layer Violation: '{violating_mod.inferred_layer}' Directly Imports '{target_mod.inferred_layer}'",
        description=description,
        evidence=evidence,
        impact=rule.impact_template,
        recommendation=rule.recommendation_template,
        fingerprint=fingerprint,
        metadata={
            "violating_layer": violating_mod.inferred_layer,
            "target_layer": target_mod.inferred_layer,
            "target_module": target_mod.module_name,
        },
    )


def create_inconsistent_config_finding(
    mod: ModuleNode,
    line_start: int,
    line_end: int,
    snippet: str,
    centralized_configs: list[str],
) -> Finding:
    """Generate ENT-ARCH-004 finding for direct os.environ access when centralized config exists."""
    rule = RULE_ENT_ARCH_004
    cfg_list = ", ".join(f"`{c}`" for c in centralized_configs[:3])
    description = (
        f"{rule.description}\n\n"
        f"Module: `{mod.file_path}` accesses environment variables directly, bypassing "
        f"established centralized configuration module(s): {cfg_list}."
    )

    evidence = CodeEvidence(
        content=snippet,
        line_start=line_start,
        line_end=line_end,
        highlight_lines=[line_start],
    )

    sig_raw = f"{rule.rule_id}:{mod.file_path}:{line_start}"
    finding_id = hashlib.sha256(sig_raw.encode("utf-8")).hexdigest()[:16]
    fingerprint = hashlib.sha256(f"{rule.rule_id}:{mod.file_path}:{line_start}".encode()).hexdigest()[:16]

    return Finding(
        id=finding_id,
        category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
        rule_id=rule.rule_id,
        severity=rule.default_severity,
        confidence=rule.default_confidence,
        file=mod.file_path,
        line_start=line_start,
        line_end=line_end,
        symbol=mod.module_name,
        title="Inconsistent Configuration Access Bypasses Centralized Settings",
        description=description,
        evidence=evidence,
        impact=rule.impact_template,
        recommendation=rule.recommendation_template,
        fingerprint=fingerprint,
        metadata={
            "centralized_config_modules": centralized_configs,
        },
    )


def create_god_module_finding(
    mod: ModuleNode,
    responsibilities: list[ArchitecturalResponsibility],
) -> Finding:
    """Generate ENT-ARCH-005 finding for God Module."""
    rule = RULE_ENT_ARCH_005
    evidence_items = []
    for r in responsibilities:
        notes = mod.responsibility_evidence.get(r, [])
        evidence_items.append(f"- **{r.value}**: {'; '.join(notes)}")

    description = (
        f"{rule.description}\n\n"
        f"Module: `{mod.file_path}` ({mod.loc} LOC, {len(mod.functions)} functions, {len(mod.classes)} classes)\n"
        f"Concentrates {len(responsibilities)} Orthogonal Architectural Responsibilities:\n"
        + "\n".join(evidence_items)
    )

    lines = mod.source_code.splitlines()
    snippet_content = "\n".join(lines[: min(12, len(lines))])
    evidence = CodeEvidence(
        content=snippet_content,
        line_start=1,
        line_end=min(12, len(lines)),
        highlight_lines=[1],
    )

    sig_raw = f"{rule.rule_id}:{mod.file_path}"
    finding_id = hashlib.sha256(sig_raw.encode("utf-8")).hexdigest()[:16]
    fingerprint = hashlib.sha256(f"{rule.rule_id}:{mod.file_path}".encode()).hexdigest()[:16]

    return Finding(
        id=finding_id,
        category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
        rule_id=rule.rule_id,
        severity=rule.default_severity,
        confidence=rule.default_confidence,
        file=mod.file_path,
        line_start=1,
        line_end=min(12, len(lines)),
        symbol=mod.module_name,
        title=f"God Module: {len(responsibilities)} Distinct Architectural Responsibilities in '{mod.module_name}'",
        description=description,
        evidence=evidence,
        impact=rule.impact_template,
        recommendation=rule.recommendation_template,
        fingerprint=fingerprint,
        metadata={
            "responsibilities": [r.value for r in responsibilities],
            "loc": mod.loc,
            "function_count": len(mod.functions),
            "class_count": len(mod.classes),
        },
    )


def create_god_class_finding(
    mod: ModuleNode,
    class_name: str,
    method_count: int,
    line_start: int,
    line_end: int,
    snippet: str,
    responsibilities: list[str],
) -> Finding:
    """Generate ENT-ARCH-006 finding for God Class."""
    rule = RULE_ENT_ARCH_006
    description = (
        f"{rule.description}\n\n"
        f"Class: `{class_name}` in `{mod.file_path}` contains {method_count} methods "
        f"and combines multiple distinct domain responsibilities ({', '.join(responsibilities)})."
    )

    evidence = CodeEvidence(
        content=snippet,
        line_start=line_start,
        line_end=line_end,
        highlight_lines=[line_start],
    )

    sig_raw = f"{rule.rule_id}:{mod.file_path}:{class_name}"
    finding_id = hashlib.sha256(sig_raw.encode("utf-8")).hexdigest()[:16]
    fingerprint = hashlib.sha256(f"{rule.rule_id}:{mod.file_path}:{class_name}".encode()).hexdigest()[:16]

    return Finding(
        id=finding_id,
        category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
        rule_id=rule.rule_id,
        severity=rule.default_severity,
        confidence=rule.default_confidence,
        file=mod.file_path,
        line_start=line_start,
        line_end=line_end,
        symbol=class_name,
        title=f"God Class: '{class_name}' with {method_count} Methods Combining Multiple Responsibilities",
        description=description,
        evidence=evidence,
        impact=rule.impact_template,
        recommendation=rule.recommendation_template,
        fingerprint=fingerprint,
        metadata={
            "class_name": class_name,
            "method_count": method_count,
            "responsibilities": responsibilities,
        },
    )


def create_cross_layer_coupling_finding(
    mod: ModuleNode,
    connected_layers: list[ArchitecturalLayer],
) -> Finding:
    """Generate ENT-ARCH-007 finding for excessive cross-layer coupling."""
    rule = RULE_ENT_ARCH_007
    layer_names = ", ".join(layer.value for layer in connected_layers)
    description = (
        f"{rule.description}\n\n"
        f"Module: `{mod.file_path}` directly imports from {len(connected_layers)} different architectural layers:\n"
        f"  Connected Layers: {layer_names}"
    )

    lines = mod.source_code.splitlines()
    snippet_content = "\n".join(lines[: min(10, len(lines))])
    evidence = CodeEvidence(
        content=snippet_content,
        line_start=1,
        line_end=min(10, len(lines)),
        highlight_lines=[1],
    )

    sig_raw = f"{rule.rule_id}:{mod.file_path}"
    finding_id = hashlib.sha256(sig_raw.encode("utf-8")).hexdigest()[:16]
    fingerprint = hashlib.sha256(f"{rule.rule_id}:{mod.file_path}".encode()).hexdigest()[:16]

    return Finding(
        id=finding_id,
        category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
        rule_id=rule.rule_id,
        severity=rule.default_severity,
        confidence=rule.default_confidence,
        file=mod.file_path,
        line_start=1,
        line_end=min(10, len(lines)),
        symbol=mod.module_name,
        title=f"Excessive Cross-Layer Coupling: Direct Dependencies Across {len(connected_layers)} Architectural Layers",
        description=description,
        evidence=evidence,
        impact=rule.impact_template,
        recommendation=rule.recommendation_template,
        fingerprint=fingerprint,
        metadata={
            "connected_layers": [layer.value for layer in connected_layers],
            "layer_count": len(connected_layers),
        },
    )


def create_inconsistent_dependency_finding(
    mod: ModuleNode,
    dep_name: str,
    line_start: int,
    line_end: int,
    snippet: str,
) -> Finding:
    """Generate ENT-ARCH-003 finding for inconsistent dependency acquisition."""
    rule = RULE_ENT_ARCH_003
    description = (
        f"{rule.description}\n\n"
        f"Endpoint in `{mod.file_path}` manually instantiates dependency `{dep_name}` directly, "
        f"while peer endpoints in the same module use framework dependency injection."
    )

    evidence = CodeEvidence(
        content=snippet,
        line_start=line_start,
        line_end=line_end,
        highlight_lines=[line_start],
    )

    sig_raw = f"{rule.rule_id}:{mod.file_path}:{line_start}:{dep_name}"
    finding_id = hashlib.sha256(sig_raw.encode("utf-8")).hexdigest()[:16]
    fingerprint = hashlib.sha256(f"{rule.rule_id}:{mod.file_path}:{line_start}".encode()).hexdigest()[:16]

    return Finding(
        id=finding_id,
        category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
        rule_id=rule.rule_id,
        severity=rule.default_severity,
        confidence=rule.default_confidence,
        file=mod.file_path,
        line_start=line_start,
        line_end=line_end,
        symbol=mod.module_name,
        title=f"Inconsistent Dependency Pattern: Manual Instantiation of '{dep_name}'",
        description=description,
        evidence=evidence,
        impact=rule.impact_template,
        recommendation=rule.recommendation_template,
        fingerprint=fingerprint,
        metadata={
            "dependency": dep_name,
        },
    )


def create_inconsistent_pattern_finding(
    mod: ModuleNode,
    observed_flow: str,
    dominant_flow: str,
    line_start: int,
    line_end: int,
    snippet: str,
) -> Finding:
    """Generate ENT-ARCH-008 finding for divergent architectural pattern."""
    rule = RULE_ENT_ARCH_008
    description = (
        f"{rule.description}\n\n"
        f"Module `{mod.file_path}` follows `{observed_flow}`, diverging from the dominant "
        f"architectural pattern `{dominant_flow}` established by peer modules."
    )

    evidence = CodeEvidence(
        content=snippet,
        line_start=line_start,
        line_end=line_end,
        highlight_lines=[line_start],
    )

    sig_raw = f"{rule.rule_id}:{mod.file_path}:{line_start}"
    finding_id = hashlib.sha256(sig_raw.encode("utf-8")).hexdigest()[:16]
    fingerprint = hashlib.sha256(f"{rule.rule_id}:{mod.file_path}:{line_start}".encode()).hexdigest()[:16]

    return Finding(
        id=finding_id,
        category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
        rule_id=rule.rule_id,
        severity=rule.default_severity,
        confidence=rule.default_confidence,
        file=mod.file_path,
        line_start=line_start,
        line_end=line_end,
        symbol=mod.module_name,
        title=f"Inconsistent Architectural Pattern: Follows '{observed_flow}' Instead of '{dominant_flow}'",
        description=description,
        evidence=evidence,
        impact=rule.impact_template,
        recommendation=rule.recommendation_template,
        fingerprint=fingerprint,
        metadata={
            "observed_flow": observed_flow,
            "dominant_flow": dominant_flow,
        },
    )

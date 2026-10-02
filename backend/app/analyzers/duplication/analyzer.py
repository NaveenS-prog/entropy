"""Code Duplication & Boilerplate Debt Analyzer for Entropy Phase 8.

Performs deterministic static analysis on normalized Python ASTs to detect:
1. Exact structural duplication across functions ($p1, $v1 anonymized) [ENT-DUP-001]
2. Structurally similar functions (>= 80% similarity) [ENT-DUP-002]
3. Repeated structural boilerplate patterns [ENT-DUP-003]
4. Cross-file structural duplication [ENT-DUP-004]
5. Duplication clusters of 3+ similar functions [ENT-DUP-005]

Strict Invariants:
- 100% static analysis: target repository code is NEVER executed or imported.
- Deterministic: identical inputs produce identical finding IDs, fingerprints, and scores.
- Zero AI / LLM involvement in finding generation.
"""

from __future__ import annotations

import ast
import logging

from app.analyzers.base import AnalysisContext, BaseAnalyzer
from app.analyzers.duplication.clustering import DuplicationDetector
from app.analyzers.duplication.models import FunctionSignature
from app.analyzers.duplication.normalizer import normalize_python_function
from app.analyzers.duplication.rules import (
    ALL_DUPLICATION_RULES,
    create_finding_for_boilerplate,
    create_finding_for_cluster,
)
from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition

logger = logging.getLogger("entropy.analyzers.duplication")


class CodeDuplicationDebtAnalyzer(BaseAnalyzer):
    """Static analyzer identifying structural duplication and boilerplate debt."""

    def __init__(self, detector: DuplicationDetector | None = None) -> None:
        self.detector = detector or DuplicationDetector()

    @property
    def analyzer_id(self) -> str:
        return "code_duplication_debt_analyzer"

    @property
    def name(self) -> str:
        return "Code Duplication & Boilerplate Debt Analyzer"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.CODE_DUPLICATION

    @property
    def supported_languages(self) -> set[SupportedLanguage]:
        return {SupportedLanguage.PYTHON}

    @property
    def rules(self) -> list[RuleDefinition]:
        return ALL_DUPLICATION_RULES

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Execute deterministic duplication analysis across the repository context."""
        python_contexts = context.get_valid_python_contexts()
        if not python_contexts:
            return []

        # 1. Extract and normalize all functions across Python contexts
        all_signatures: list[FunctionSignature] = []

        for ctx in python_contexts:
            if not ctx.ast_root:
                continue

            # Walk AST to find all top-level and class-level functions
            for node in ast.walk(ctx.ast_root):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    try:
                        sig = normalize_python_function(node, ctx.file_path, ctx.source_code)
                        if sig is not None:
                            all_signatures.append(sig)
                    except Exception as e:
                        logger.warning(
                            "Failed to normalize function '%s' in '%s': %s",
                            node.name,
                            ctx.file_path,
                            e,
                        )

        if len(all_signatures) < 2:
            return []

        # 2. Run deterministic clustering and boilerplate detection
        clusters, boilerplate_patterns = self.detector.find_duplications(all_signatures)

        # 3. Create structured findings
        findings: list[Finding] = []

        for cluster in clusters:
            finding = create_finding_for_cluster(cluster)
            findings.append(finding)

        for bp in boilerplate_patterns:
            finding = create_finding_for_boilerplate(bp)
            findings.append(finding)

        # 4. Sort findings deterministically
        findings.sort(key=lambda f: (f.file, f.line_start, f.rule_id, f.id))

        logger.info(
            "Code Duplication analyzer completed: %d finding(s) across %d signatures",
            len(findings),
            len(all_signatures),
        )
        return findings

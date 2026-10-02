"""Architectural Consistency & Architecture Debt Analyzer for Entropy Phase 9."""

from __future__ import annotations

import logging

from app.analyzers.architecture.graph import DependencyGraph
from app.analyzers.architecture.inference import ArchitectureModelBuilder
from app.analyzers.architecture.models import (
    ArchitecturalLayer,
    ArchitectureModel,
    ModuleNode,
)
from app.analyzers.architecture.rules import (
    ALL_ARCHITECTURE_RULES,
    create_circular_dependency_finding,
    create_cross_layer_coupling_finding,
    create_god_class_finding,
    create_god_module_finding,
    create_inconsistent_config_finding,
    create_inconsistent_dependency_finding,
    create_inconsistent_pattern_finding,
    create_layer_violation_finding,
)
from app.analyzers.base import AnalysisContext, BaseAnalyzer
from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition

logger = logging.getLogger("entropy.analyzers.architecture")


class ArchitecturalConsistencyAnalyzer(BaseAnalyzer):
    """Deterministic static analyzer for identifying architectural consistency debt."""

    @property
    def analyzer_id(self) -> str:
        return "architectural_consistency_analyzer"

    @property
    def name(self) -> str:
        return "Architectural Consistency Debt Analyzer"

    @property
    def category(self) -> DebtCategory:
        return DebtCategory.ARCHITECTURAL_CONSISTENCY

    @property
    def supported_languages(self) -> set[SupportedLanguage]:
        return {SupportedLanguage.PYTHON}

    @property
    def rules(self) -> list[RuleDefinition]:
        return ALL_ARCHITECTURE_RULES

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Execute deterministic architecture analysis across the repository context."""
        findings: list[Finding] = []

        # 1. Build ArchitectureModel and DependencyGraph
        builder = ArchitectureModelBuilder(context)
        model = builder.build()
        graph = DependencyGraph(model.modules)

        logger.info(
            "Built architecture model with %d module(s) across %d packages",
            len(model.modules),
            len(model.package_hierarchy),
        )

        # 2. ENT-ARCH-001: Circular Module Dependencies
        findings.extend(self._detect_circular_dependencies(graph, model))

        # 3. ENT-ARCH-002: Architectural Layer Boundary Violations
        findings.extend(self._detect_layer_boundary_violations(model))

        # 4. ENT-ARCH-003: Inconsistent Dependency Patterns
        findings.extend(self._detect_inconsistent_dependencies(context, model))

        # 5. ENT-ARCH-004: Inconsistent Configuration Access
        findings.extend(self._detect_inconsistent_config_access(context, model))

        # 6. ENT-ARCH-005: God Module / Excessively Responsible Module
        findings.extend(self._detect_god_modules(model))

        # 7. ENT-ARCH-006: God Class / Excessively Responsible Class
        findings.extend(self._detect_god_classes(model))

        # 8. ENT-ARCH-007: Excessive Cross-Layer Coupling
        findings.extend(self._detect_cross_layer_coupling(model))

        # 9. ENT-ARCH-008: Inconsistent Architectural Patterns
        findings.extend(self._detect_inconsistent_patterns(context, model))

        # Sort findings deterministically
        findings.sort(key=lambda f: (f.file, f.line_start, f.rule_id, f.id))
        logger.info("Architectural analyzer completed with %d finding(s)", len(findings))
        return findings

    # -------------------------------------------------------------------------
    # Rule 1: ENT-ARCH-001 Circular Module Dependencies
    # -------------------------------------------------------------------------

    def _detect_circular_dependencies(
        self, graph: DependencyGraph, model: ArchitectureModel
    ) -> list[Finding]:
        findings: list[Finding] = []
        cycles = graph.find_cycles()

        for cycle in cycles:
            primary_name = cycle.cycle_path[0]
            primary_mod = model.modules.get(primary_name)
            if primary_mod:
                findings.append(create_circular_dependency_finding(cycle, primary_mod))

        return findings

    # -------------------------------------------------------------------------
    # Rule 2: ENT-ARCH-002 Architectural Layer Boundary Violations
    # -------------------------------------------------------------------------

    def _detect_layer_boundary_violations(self, model: ArchitectureModel) -> list[Finding]:
        findings: list[Finding] = []

        service_modules = model.modules_by_layer.get(ArchitecturalLayer.SERVICE, [])
        repo_modules = model.modules_by_layer.get(ArchitecturalLayer.REPOSITORY, [])
        api_modules = model.modules_by_layer.get(ArchitecturalLayer.API, [])

        # Only evaluate if the repository has an observable intermediate Service layer
        # and an observable Repository layer (evidence of layered architecture)
        if not service_modules or not repo_modules or not api_modules:
            return findings

        # Check if majority of API modules use Service modules
        api_using_services = [
            m_name
            for m_name in api_modules
            if any(svc in model.modules[m_name].local_dependencies for svc in service_modules)
        ]

        if len(api_using_services) >= 1 or len(service_modules) >= 2:
            # Established convention: API routes delegate to services
            for api_name in sorted(api_modules):
                api_mod = model.modules[api_name]
                for target_name in sorted(api_mod.local_dependencies):
                    target_mod = model.modules.get(target_name)
                    if target_mod and target_mod.inferred_layer == ArchitecturalLayer.REPOSITORY:
                        # Direct jump from API to Repository bypassing Service
                        # Find import line in API module
                        line_start = 1
                        line_end = 1
                        snippet = f"# Direct import of repository: {target_mod.file_path}"
                        for imp in api_mod.imports:
                            if (
                                imp.module == target_name
                                or imp.name == target_name
                                or (imp.module and target_name.endswith(imp.module))
                            ):
                                line_start = imp.location.line_start
                                line_end = imp.location.line_end
                                lines = api_mod.source_code.splitlines()
                                snippet = "\n".join(
                                    lines[max(0, line_start - 1) : min(len(lines), line_end + 1)]
                                )
                                break

                        findings.append(
                            create_layer_violation_finding(
                                violating_mod=api_mod,
                                target_mod=target_mod,
                                expected_layer="service",
                                line_start=line_start,
                                line_end=line_end,
                                snippet=snippet,
                            )
                        )

        return findings

    # -------------------------------------------------------------------------
    # Rule 3: ENT-ARCH-003 Inconsistent Dependency Patterns
    # -------------------------------------------------------------------------

    def _detect_inconsistent_dependencies(
        self, context: AnalysisContext, model: ArchitectureModel
    ) -> list[Finding]:
        findings: list[Finding] = []

        api_modules = [
            model.modules[name]
            for name in model.modules_by_layer.get(ArchitecturalLayer.API, [])
            if name in model.modules
        ]

        for mod in api_modules:
            py_ctx = context.get_python_context(mod.file_path)
            if not py_ctx or not py_ctx.ast_root:
                continue

            # Check if module uses dependency injection (e.g. Depends)
            has_di = any("Depends" in imp.name for imp in mod.imports) or "Depends(" in mod.source_code
            if not has_di:
                continue

            # Look for manual instantiation of services or db sessions inside route handlers
            for fn in mod.functions:
                is_route = any(
                    dec.name.startswith("router.") or dec.name.startswith("app.")
                    for dec in fn.decorators
                )
                if not is_route:
                    continue

                # Check if this route uses Depends
                fn_uses_di = any("Depends" in str(p.default_value or "") for p in fn.parameters)

                # Look for manual instantiations in function body (e.g. UserService(), SessionLocal(), db = get_db())
                for call in py_ctx.structure.all_calls:
                    if call.enclosing_function == fn.name:
                        c_name = call.callable_name
                        if c_name.endswith("Service") or c_name in ("SessionLocal", "get_db", "get_session"):
                            if not fn_uses_di:
                                # Inconsistent: Route instantiates dependency directly while module uses DI
                                snippet = py_ctx.extract_snippet(
                                    call.location.line_start, call.location.line_end
                                ).content
                                findings.append(
                                    create_inconsistent_dependency_finding(
                                        mod=mod,
                                        dep_name=c_name,
                                        line_start=call.location.line_start,
                                        line_end=call.location.line_end,
                                        snippet=snippet,
                                    )
                                )

        return findings

    # -------------------------------------------------------------------------
    # Rule 4: ENT-ARCH-004 Inconsistent Configuration Access
    # -------------------------------------------------------------------------

    def _detect_inconsistent_config_access(
        self, context: AnalysisContext, model: ArchitectureModel
    ) -> list[Finding]:
        findings: list[Finding] = []

        if not model.has_centralized_config or not model.centralized_config_modules:
            return findings

        # Check API and Service modules for direct os.environ / os.getenv access
        target_layers = (ArchitecturalLayer.API, ArchitecturalLayer.SERVICE)
        for mod in model.modules.values():
            if mod.inferred_layer not in target_layers:
                continue
            if any(cfg in mod.module_name for cfg in model.centralized_config_modules):
                continue

            py_ctx = context.get_python_context(mod.file_path)
            if not py_ctx or not py_ctx.ast_root:
                continue

            for call in py_ctx.structure.all_calls:
                c_name = call.callable_name
                if c_name in ("os.getenv", "os.environ.get") or call.expression.startswith("os.environ"):
                    snippet = py_ctx.extract_snippet(
                        call.location.line_start, call.location.line_end
                    ).content
                    findings.append(
                        create_inconsistent_config_finding(
                            mod=mod,
                            line_start=call.location.line_start,
                            line_end=call.location.line_end,
                            snippet=snippet,
                            centralized_configs=model.centralized_config_modules,
                        )
                    )

        return findings

    # -------------------------------------------------------------------------
    # Rule 5: ENT-ARCH-005 God Module
    # -------------------------------------------------------------------------

    def _detect_god_modules(self, model: ArchitectureModel) -> list[Finding]:
        findings: list[Finding] = []

        for mod in model.modules.values():
            # Concentrates 4 or more orthogonal responsibilities AND has non-trivial size
            resp_count = len(mod.responsibilities)
            if resp_count >= 4 and (mod.loc >= 100 or len(mod.functions) + len(mod.classes) >= 6):
                sorted_resps = sorted(mod.responsibilities, key=lambda r: r.value)
                findings.append(create_god_module_finding(mod, sorted_resps))

        return findings

    # -------------------------------------------------------------------------
    # Rule 6: ENT-ARCH-006 God Class
    # -------------------------------------------------------------------------

    def _detect_god_classes(self, model: ArchitectureModel) -> list[Finding]:
        findings: list[Finding] = []

        for mod in model.modules.values():
            for cls in mod.classes:
                method_count = len(cls.methods)
                # Check method names for multi-domain divergence
                m_names = [m.name.lower() for m in cls.methods]
                domains: set[str] = set()

                if any(k in m for m in m_names for k in ("handle", "route", "get_", "post_", "request")):
                    domains.add("routing_http")
                if any(k in m for m in m_names for k in ("save", "query", "find_", "delete_", "commit")):
                    domains.add("persistence_db")
                if any(k in m for m in m_names for k in ("auth", "hash", "token", "verify_pass", "login")):
                    domains.add("auth_security")
                if any(k in m for m in m_names for k in ("config", "load_env", "settings")):
                    domains.add("config_management")
                if any(k in m for m in m_names for k in ("process", "calculate", "execute_step", "validate")):
                    domains.add("business_logic")

                # If class has >= 10 methods and combines 3 or more distinct domains
                if method_count >= 10 and len(domains) >= 3:
                    lines = mod.source_code.splitlines()
                    start = cls.location.line_start
                    end = min(start + 8, len(lines))
                    snippet = "\n".join(lines[max(0, start - 1) : end])

                    findings.append(
                        create_god_class_finding(
                            mod=mod,
                            class_name=cls.name,
                            method_count=method_count,
                            line_start=cls.location.line_start,
                            line_end=min(cls.location.line_start + 15, cls.location.line_end),
                            snippet=snippet,
                            responsibilities=sorted(domains),
                        )
                    )

        return findings

    # -------------------------------------------------------------------------
    # Rule 7: ENT-ARCH-007 Excessive Cross-Layer Coupling
    # -------------------------------------------------------------------------

    def _detect_cross_layer_coupling(self, model: ArchitectureModel) -> list[Finding]:
        findings: list[Finding] = []

        for mod in model.modules.values():
            # Application Composition Roots are designed to wire together multiple layers
            if mod.is_composition_root:
                continue

            # Collect layers of all local dependencies
            dep_layers: set[ArchitecturalLayer] = set()
            for dep_name in mod.local_dependencies:
                dep_mod = model.modules.get(dep_name)
                if dep_mod and dep_mod.inferred_layer != ArchitecturalLayer.UNKNOWN:
                    dep_layers.add(dep_mod.inferred_layer)

            # If module imports from 4 or more distinct layers simultaneously
            if len(dep_layers) >= 4 and mod.inferred_layer not in (
                ArchitecturalLayer.UNKNOWN,
                ArchitecturalLayer.UTILITY,
            ):
                sorted_layers = sorted(dep_layers, key=lambda layer_item: layer_item.value)
                findings.append(create_cross_layer_coupling_finding(mod, sorted_layers))

        return findings

    # -------------------------------------------------------------------------
    # Rule 8: ENT-ARCH-008 Inconsistent Architectural Patterns
    # -------------------------------------------------------------------------

    def _detect_inconsistent_patterns(
        self, context: AnalysisContext, model: ArchitectureModel
    ) -> list[Finding]:
        findings: list[Finding] = []

        api_modules = [
            model.modules[name]
            for name in model.modules_by_layer.get(ArchitecturalLayer.API, [])
            if name in model.modules
        ]

        # Check if there is an established dominant architectural pattern among API modules
        # Pattern A: API -> Service
        # Outlier: API -> direct raw query without Service
        service_users = [
            m
            for m in api_modules
            if any(
                model.modules.get(dep, ModuleNode("", "", "", 0, 0, False)).inferred_layer
                == ArchitecturalLayer.SERVICE
                for dep in m.local_dependencies
            )
        ]

        if len(api_modules) >= 3 and len(service_users) / len(api_modules) >= 0.65:
            # Dominant pattern: Route -> Service
            for m in api_modules:
                if m not in service_users:
                    # Check if this outlier does direct raw DB access
                    has_direct_db = (
                        "raw_sql" in m.source_code
                        or "cursor.execute" in m.source_code
                        or any("db" in dep for dep in m.local_dependencies)
                    )
                    if has_direct_db:
                        py_ctx = context.get_python_context(m.file_path)
                        line_start = 1
                        line_end = min(8, m.loc)
                        snippet = f"# Outlier pattern in {m.file_path}"
                        if py_ctx:
                            snippet = py_ctx.extract_snippet(line_start, line_end).content

                        findings.append(
                            create_inconsistent_pattern_finding(
                                mod=m,
                                observed_flow="Route -> Direct Database Access",
                                dominant_flow="Route -> Service Layer",
                                line_start=line_start,
                                line_end=line_end,
                                snippet=snippet,
                            )
                        )

        return findings

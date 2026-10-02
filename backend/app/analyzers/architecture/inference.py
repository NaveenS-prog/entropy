"""Evidence-based architectural model building, layer inference, and responsibility detection."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.analyzers.architecture.models import (
    ArchitecturalLayer,
    ArchitecturalResponsibility,
    ArchitectureModel,
    ModuleNode,
)
from app.analyzers.context import AnalysisContext, PythonASTContext

# Paths to strictly exclude from architecture debt scanning
EXCLUDED_PATH_SUBSTRINGS: tuple[str, ...] = (
    "test/",
    "tests/",
    "fixtures/",
    "fixture/",
    "migrations/",
    "alembic/",
    "vendor/",
    "node_modules/",
    ".venv/",
    "venv/",
    "env/",
    "dist/",
    "build/",
    "scripts/",
    "setup.py",
)


def is_path_excluded(file_path: str) -> bool:
    """Check if file_path is within test, fixture, migration, or virtualenv directories."""
    norm = file_path.replace("\\", "/").lower()
    return any(sub in norm for sub in EXCLUDED_PATH_SUBSTRINGS) or norm.startswith("test_")


class ArchitectureModelBuilder:
    """Extracts modules, dependencies, and architectural metadata from AnalysisContext."""

    def __init__(self, context: AnalysisContext) -> None:
        self.context = context
        self.modules: dict[str, ModuleNode] = {}
        self.modules_by_path: dict[str, ModuleNode] = {}
        # Path lookup aliases: alias -> canonical module_name
        self._alias_map: dict[str, str] = {}

    def build(self) -> ArchitectureModel:
        """Construct the complete ArchitectureModel."""
        valid_contexts = [
            ctx
            for ctx in self.context.get_valid_python_contexts()
            if not is_path_excluded(ctx.file_path)
        ]

        # 1. First pass: Register all modules and compute import aliases
        for ctx in valid_contexts:
            self._register_module(ctx)

        # 2. Second pass: Resolve imports into local vs external dependencies
        for ctx in valid_contexts:
            self._resolve_dependencies(ctx)

        # 3. Third pass: Infer architectural layers and responsibilities
        for mod in self.modules.values():
            self._infer_layer(mod)
            self._infer_responsibilities(mod)

        # 4. Fourth pass: Identify repository-wide architectural conventions
        model = ArchitectureModel(
            modules=self.modules,
            modules_by_path=self.modules_by_path,
        )
        self._detect_repository_conventions(model)

        return model

    def _register_module(self, ctx: PythonASTContext) -> None:
        """Create ModuleNode and record module name aliases."""
        path = ctx.file_path.replace("\\", "/")
        path_obj = Path(path)

        # Canonical module name based on path components
        parts = list(path_obj.with_suffix("").parts)
        is_init = path_obj.name == "__init__.py"
        if is_init and parts:
            parts.pop()

        canonical_name = ".".join(parts)
        package_name = ".".join(parts[:-1]) if len(parts) > 1 else ""
        depth = len(parts)

        # Record aliases:
        # e.g. for backend/app/services/user.py:
        # aliases: backend.app.services.user, app.services.user, services.user
        for i in range(len(parts)):
            sub_alias = ".".join(parts[i:])
            self._alias_map[sub_alias] = canonical_name

        classes = list(ctx.structure.classes)
        functions = list(ctx.structure.functions)
        public_symbols = [
            fn.name for fn in functions if not fn.name.startswith("_")
        ] + [cls.name for cls in classes if not cls.name.startswith("_")]
        calls = list(ctx.structure.all_calls)

        # Statically detect if module acts as an Application Composition Root / Entrypoint
        framework_app_callables = (
            "FastAPI",
            "Flask",
            "Starlette",
            "Sanic",
            "Tornado",
            "Bottle",
            "AiohttpApp",
            "WSGIApplication",
        )
        is_comp_root = False
        for call in calls:
            c_name = call.callable_name
            if (
                c_name in framework_app_callables
                or any(c_name.endswith(f".{app_cls}") for app_cls in framework_app_callables)
                or c_name.endswith(".include_router")
                or c_name.endswith(".register_blueprint")
                or c_name in ("uvicorn.run", "app.run")
            ):
                is_comp_root = True
                break

        mod = ModuleNode(
            file_path=path,
            module_name=canonical_name,
            package_name=package_name,
            package_depth=depth,
            loc=len(ctx.lines),
            is_package_init=is_init,
            imports=list(ctx.structure.imports),
            classes=classes,
            functions=functions,
            public_symbols=public_symbols,
            calls=calls,
            is_composition_root=is_comp_root,
            source_code=ctx.source_code,
        )

        self.modules[canonical_name] = mod
        self.modules_by_path[path] = mod

    def _resolve_dependencies(self, ctx: PythonASTContext) -> None:
        """Resolve import statements into local project vs external dependencies."""
        path = ctx.file_path.replace("\\", "/")
        path_obj = Path(path)
        parts = list(path_obj.with_suffix("").parts)
        if path_obj.name == "__init__.py" and parts:
            parts.pop()
        canonical_name = ".".join(parts)
        mod = self.modules.get(canonical_name)
        if not mod:
            return

        for imp in mod.imports:
            target_module = self._resolve_import_target(imp, parts)
            if target_module and target_module in self.modules:
                mod.local_dependencies.add(target_module)
                mod.imported_symbols[imp.name] = target_module
            else:
                # External dependency (standard library or third-party)
                ext_name = imp.module.split(".")[0] if imp.module else imp.name.split(".")[0]
                mod.external_dependencies.add(ext_name)

    def _resolve_import_target(self, imp: Any, source_parts: list[str]) -> str | None:
        """Statically resolve an ImportItem to a canonical local module name."""
        if imp.level > 0:
            # Relative import
            # level 1 = current package, level 2 = parent package, etc.
            pkg_parts = source_parts[:-1] if len(source_parts) > 1 else []
            up_levels = imp.level - 1
            if up_levels > 0 and len(pkg_parts) >= up_levels:
                base_pkg = pkg_parts[:-up_levels]
            else:
                base_pkg = pkg_parts

            if imp.module:
                target_str = ".".join(base_pkg + [imp.module])
            else:
                target_str = ".".join(base_pkg)

            # Check if target_str matches an alias
            if target_str in self._alias_map:
                return self._alias_map[target_str]
            # Try combining with imported symbol name (e.g. from . import user)
            target_with_name = f"{target_str}.{imp.name}" if target_str else imp.name
            if target_with_name in self._alias_map:
                return self._alias_map[target_with_name]
            return None

        # Absolute import
        raw_mod = imp.module or imp.name
        # Direct match or alias lookup
        if raw_mod in self._alias_map:
            return self._alias_map[raw_mod]

        # Check subcomponents if e.g. from app.services.user import get_user
        # where user is the module and get_user is a function
        if imp.module and imp.module in self._alias_map:
            return self._alias_map[imp.module]

        # Check if raw_mod + name matches a module (e.g. import app.services.user)
        full_candidate = f"{raw_mod}.{imp.name}" if imp.module else raw_mod
        if full_candidate in self._alias_map:
            return self._alias_map[full_candidate]

        # Suffix matching across alias map
        for alias, c_name in self._alias_map.items():
            if raw_mod == alias or raw_mod.endswith(f".{alias}"):
                return c_name

        return None

    def _infer_layer(self, mod: ModuleNode) -> None:
        """Infer the architectural layer of a module based on path and AST evidence."""
        p_lower = mod.file_path.lower().replace("\\", "/")
        path_parts = set(Path(p_lower).parts)
        imports_lower = {imp.module.lower() for imp in mod.imports if imp.module} | {
            imp.name.lower() for imp in mod.imports
        }

        # Helper to match directory or segment
        def has_segment(names: tuple[str, ...]) -> bool:
            return any(name in path_parts or f"/{name}/" in f"/{p_lower}" for name in names)

        # 1. API / Presentation layer
        is_api = has_segment(("api", "routes", "routers", "controllers", "views", "endpoints"))
        has_route_imports = any(
            pkg in imports_lower for pkg in ("fastapi", "flask", "django.urls", "starlette")
        )
        has_route_decorators = False
        for fn in mod.functions:
            for dec in fn.decorators:
                if any(
                    dec.name.startswith(p)
                    for p in ("router.", "app.", "blueprint.", "route", "api_view")
                ):
                    has_route_decorators = True
                    break

        if is_api or (has_route_imports and has_route_decorators):
            mod.inferred_layer = ArchitecturalLayer.API
            mod.layer_confidence = 0.9 if (is_api and has_route_decorators) else 0.7
            return

        # 2. Repository / Persistence layer
        is_repo = has_segment(("repositories", "repository", "persistence", "dao", "database", "db"))
        has_orm_imports = any(
            pkg in imports_lower
            for pkg in ("sqlalchemy", "tortoise", "django.db", "pymongo", "psycopg", "peewee")
        )
        if is_repo or (has_orm_imports and "repository" in mod.module_name.lower()):
            mod.inferred_layer = ArchitecturalLayer.REPOSITORY
            mod.layer_confidence = 0.85
            return

        # 3. Model / Schema layer
        is_model = has_segment(("models", "schemas", "entities", "dto", "serializers"))
        if is_model and not is_repo:
            mod.inferred_layer = ArchitecturalLayer.MODEL
            mod.layer_confidence = 0.85
            return

        # 4. Service layer
        is_service = has_segment(("services", "service", "domain", "use_cases", "workflows"))
        if is_service:
            mod.inferred_layer = ArchitecturalLayer.SERVICE
            mod.layer_confidence = 0.85
            return

        # 5. Config layer
        is_config = has_segment(("config", "settings", "configuration")) or any(
            name in p_lower for name in ("config.py", "settings.py")
        )
        if is_config:
            mod.inferred_layer = ArchitecturalLayer.CONFIG
            mod.layer_confidence = 0.9
            return

        # 6. Security / Auth layer
        is_sec = has_segment(("auth", "security", "tokens", "crypto"))
        if is_sec:
            mod.inferred_layer = ArchitecturalLayer.SECURITY
            mod.layer_confidence = 0.85
            return

        # 7. Utility layer
        is_util = has_segment(("utils", "helpers", "common", "tools"))
        if is_util:
            mod.inferred_layer = ArchitecturalLayer.UTILITY
            mod.layer_confidence = 0.75
            return

        mod.inferred_layer = ArchitecturalLayer.UNKNOWN
        mod.layer_confidence = 0.0

    def _infer_responsibilities(self, mod: ModuleNode) -> None:
        """Infer orthogonal architectural responsibilities for God Module detection."""
        # 1. Routing / HTTP
        has_routes = False
        for fn in mod.functions:
            for dec in fn.decorators:
                if any(
                    dec.name.startswith(p)
                    for p in ("router.", "app.", "route", "blueprint.", "api_view")
                ):
                    has_routes = True
                    break
        if has_routes:
            mod.responsibilities.add(ArchitecturalResponsibility.ROUTING_HTTP)
            mod.responsibility_evidence.setdefault(ArchitecturalResponsibility.ROUTING_HTTP, []).append(
                "Defines HTTP route handlers with framework decorators"
            )

        # 2. Persistence / Database
        has_db = any(
            pkg in mod.external_dependencies
            for pkg in ("sqlalchemy", "psycopg2", "psycopg", "pymongo", "tortoise", "peewee")
        )
        if not has_db:
            # Check symbols or function names
            for fn in mod.functions:
                if any(kw in fn.name.lower() for kw in ("save", "find_by", "fetch_by", "commit")):
                    has_db = True
                    break
        if has_db:
            mod.responsibilities.add(ArchitecturalResponsibility.PERSISTENCE_DB)
            mod.responsibility_evidence.setdefault(ArchitecturalResponsibility.PERSISTENCE_DB, []).append(
                "Direct database connection, ORM session, or query execution"
            )

        # 3. Auth / Security (AST imports & operations)
        auth_pkgs = {"jwt", "jose", "bcrypt", "passlib", "cryptography", "authlib"}
        has_auth_pkg = any(dep in auth_pkgs for dep in mod.external_dependencies)
        has_auth_import = any(
            (imp.module and any(p in imp.module.lower() for p in ("fastapi.security", "django.contrib.auth", "auth")))
            or (imp.name in ("OAuth2PasswordBearer", "HTTPBearer", "CryptContext", "pwd_context"))
            for imp in mod.imports
        )
        auth_ops = ("hash_password", "verify_password", "create_access_token", "decode_token", "authenticate_user", "verify_token")
        has_auth_ops = any(
            any(op in fn.name.lower() for op in auth_ops)
            for fn in mod.functions
        ) or any(
            any(op in call.callable_name.lower() for op in auth_ops)
            for call in mod.calls
        )
        if has_auth_pkg or has_auth_import or has_auth_ops:
            mod.responsibilities.add(ArchitecturalResponsibility.AUTH_SECURITY)
            mod.responsibility_evidence.setdefault(ArchitecturalResponsibility.AUTH_SECURITY, []).append(
                "Authentication, password hashing, or token verification operations"
            )

        # 4. Config Management (AST calls & settings classes)
        has_config_calls = any(
            call.callable_name in ("os.getenv", "os.environ.get")
            or call.callable_name.startswith("os.environ")
            or call.expression.startswith("os.environ[")
            for call in mod.calls
        )
        has_settings_class = any(
            any("basesettings" in str(base).lower() for base in cls.base_classes)
            for cls in mod.classes
        )
        has_config_import = "pydantic_settings" in mod.external_dependencies or any(
            imp.name in ("BaseSettings", "SettingsConfigDict") for imp in mod.imports
        )
        if has_config_calls or has_settings_class or has_config_import:
            mod.responsibilities.add(ArchitecturalResponsibility.CONFIG_MANAGEMENT)
            mod.responsibility_evidence.setdefault(ArchitecturalResponsibility.CONFIG_MANAGEMENT, []).append(
                "Accesses environment variables or manages configuration settings"
            )

        # 5. System IO (AST calls & OS process libraries)
        io_pkgs = {"subprocess", "shutil"}
        has_io_calls = any(
            call.callable_name in ("open", "os.system", "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output")
            or any(call.callable_name.startswith(p) for p in ("subprocess.", "shutil.", "os.system"))
            for call in mod.calls
        )
        if any(dep in io_pkgs for dep in mod.external_dependencies) or has_io_calls:
            mod.responsibilities.add(ArchitecturalResponsibility.SYSTEM_IO)
            mod.responsibility_evidence.setdefault(ArchitecturalResponsibility.SYSTEM_IO, []).append(
                "Low-level process execution, raw filesystem, or system I/O"
            )

        # 6. Business Logic (Dedicated domain service functions)
        if mod.inferred_layer == ArchitecturalLayer.SERVICE and len(mod.functions) >= 3:
            mod.responsibilities.add(ArchitecturalResponsibility.BUSINESS_LOGIC)
            mod.responsibility_evidence.setdefault(ArchitecturalResponsibility.BUSINESS_LOGIC, []).append(
                f"Contains {len(mod.functions)} core domain functions"
            )

    def _detect_repository_conventions(self, model: ArchitectureModel) -> None:
        """Discover repo-wide architectural conventions (e.g. centralized config, layering)."""
        # Group modules by layer
        for mod in model.modules.values():
            model.modules_by_layer.setdefault(mod.inferred_layer, []).append(mod.module_name)

        # Centralized config detection:
        config_mods = [
            m.module_name
            for m in model.modules.values()
            if m.inferred_layer == ArchitecturalLayer.CONFIG
            or any(s in m.module_name.lower() for s in ("config", "settings"))
        ]
        model.centralized_config_modules = sorted(config_mods)
        if config_mods:
            # Check how many modules depend on centralized config
            dependent_count = sum(
                1
                for m in model.modules.values()
                if any(cfg in m.local_dependencies for cfg in config_mods)
            )
            # If 3 or more modules or > 20% of modules depend on config modules, it's an established convention
            if dependent_count >= 3 or (len(model.modules) > 0 and dependent_count / len(model.modules) >= 0.15):
                model.has_centralized_config = True

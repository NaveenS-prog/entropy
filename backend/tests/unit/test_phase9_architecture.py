"""Phase 9 Architectural Consistency & Architecture Debt Analyzer Tests.

Tests all required acceptance criteria:
1. Clean architecture (0 findings, 0 score, analyzed=True)
2. Circular dependency (ENT-ARCH-001 canonical cycle detected exactly once)
3. No false cycles from external/stdlib imports
4. Layering violation (ENT-ARCH-002: API directly imports Repository when Service layer exists)
5. God module (ENT-ARCH-005: 4+ responsibilities vs clean large single-domain file)
6. God class (ENT-ARCH-006: multi-domain class vs clean focused class)
7. Configuration inconsistency (ENT-ARCH-004: direct os.environ when centralized config exists)
8. Cross-layer coupling (ENT-ARCH-007: direct coupling to 4+ layers)
9. Architectural pattern inconsistency (ENT-ARCH-008: outlier in route group)
10. Exclusions (tests, fixtures, migrations ignored)
11. Determinism across repeated scans
12. Remediation lifecycle (bad -> fix -> score drops -> restore -> score returns)
13. Malicious canary (zero code execution guarantee)
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _scan_repo_api(repo_path: Path, repo_name: str = "TestRepo"):
    """Helper to scan repository via API and return scan_id, findings, and score."""
    resp = client.post("/api/v1/repositories/scan", json={"path": str(repo_path), "repo_name": repo_name})
    assert resp.status_code == 201, f"Scan failed: {resp.text}"
    scan_id = resp.json()["scan_id"]
    findings = client.get(f"/api/v1/scans/{scan_id}/findings").json()
    score = client.get(f"/api/v1/scans/{scan_id}/score").json()
    return scan_id, findings, score


# ==============================================================================
# 1. Clean Architecture
# ==============================================================================


def test_1_clean_architecture_zero_findings(tmp_path: Path):
    """Clean layered repository produces 0 architectural findings and score of 0."""
    repo = tmp_path / "clean_repo"
    repo.mkdir()

    # Domain models
    models_dir = repo / "models"
    models_dir.mkdir()
    (models_dir / "item.py").write_text("class Item:\n    def __init__(self, name: str):\n        self.name = name\n")

    # Service layer
    services_dir = repo / "services"
    services_dir.mkdir()
    (services_dir / "item_service.py").write_text(
        "from models.item import Item\n\n"
        "class ItemService:\n"
        "    def get_items(self) -> list[Item]:\n"
        "        return [Item('alpha'), Item('beta')]\n"
    )

    # API layer delegating cleanly to Service
    api_dir = repo / "api"
    api_dir.mkdir()
    (api_dir / "router.py").write_text(
        "from fastapi import APIRouter\n"
        "from services.item_service import ItemService\n\n"
        "router = APIRouter()\n"
        "service = ItemService()\n\n"
        "@router.get('/items')\n"
        "def list_items():\n"
        "    return service.get_items()\n"
    )

    scan_id, findings, score = _scan_repo_api(repo, "Clean_Arch")
    arch_findings = [f for f in findings if f["category"] == "architectural_consistency"]
    assert len(arch_findings) == 0, f"Expected 0 findings, got: {arch_findings}"

    arch_score = score["category_scores"]["architectural_consistency"]
    assert arch_score["status"] == "analyzed"
    assert arch_score["score"] == 0.0
    assert arch_score["finding_count"] == 0


# ==============================================================================
# 2. Circular Dependency
# ==============================================================================


def test_2_circular_dependency_detected_once(tmp_path: Path):
    """Three modules forming A -> B -> C -> A produce exactly one ENT-ARCH-001 finding."""
    repo = tmp_path / "cycle_repo"
    repo.mkdir()

    (repo / "a.py").write_text("import b\ndef fn_a():\n    return b.fn_b()\n")
    (repo / "b.py").write_text("import c\ndef fn_b():\n    return c.fn_c()\n")
    (repo / "c.py").write_text("import a\ndef fn_c():\n    return a.fn_a()\n")

    scan_id, findings, score = _scan_repo_api(repo, "Cycle_Repo")
    arch_findings = [f for f in findings if f["rule_id"] == "ENT-ARCH-001"]

    # Must detect the cycle exactly once
    assert len(arch_findings) == 1
    f = arch_findings[0]
    assert "Circular Module Dependency" in f["title"]
    assert f["category"] == "architectural_consistency"
    assert f["severity"] == "medium"
    assert "cycle_path" in f["metadata"]
    assert f["metadata"]["cycle_length"] == 3


# ==============================================================================
# 3. No False Cycles from External Imports
# ==============================================================================


def test_3_no_false_cycles_from_external_imports(tmp_path: Path):
    """Standard library and third-party imports must never be treated as local cycles."""
    repo = tmp_path / "external_imports_repo"
    repo.mkdir()

    (repo / "module1.py").write_text("import os, sys, json\ndef process():\n    return json.dumps(os.environ.get('X'))\n")
    (repo / "module2.py").write_text("import sys, os\ndef run():\n    return os.path.exists(sys.executable)\n")

    scan_id, findings, score = _scan_repo_api(repo, "External_Imports")
    cycles = [f for f in findings if f["rule_id"] == "ENT-ARCH-001"]
    assert len(cycles) == 0


# ==============================================================================
# 4. Layering Violation
# ==============================================================================


def test_4_layering_boundary_violation(tmp_path: Path):
    """API directly importing Repository when Service layer exists triggers ENT-ARCH-002."""
    repo = tmp_path / "layer_repo"
    repo.mkdir()

    # Repositories
    repo_dir = repo / "repositories"
    repo_dir.mkdir()
    (repo_dir / "user_repository.py").write_text(
        "class UserRepository:\n"
        "    def query_user(self, user_id):\n"
        "        return {'id': user_id}\n"
    )

    # Services
    svc_dir = repo / "services"
    svc_dir.mkdir()
    (svc_dir / "user_service.py").write_text(
        "from repositories.user_repository import UserRepository\n\n"
        "class UserService:\n"
        "    def __init__(self):\n"
        "        self.repo = UserRepository()\n"
        "    def get_user(self, uid):\n"
        "        return self.repo.query_user(uid)\n"
    )

    # API 1: Clean (uses UserService)
    api_dir = repo / "api"
    api_dir.mkdir()
    (api_dir / "clean_routes.py").write_text(
        "from fastapi import APIRouter\n"
        "from services.user_service import UserService\n\n"
        "router = APIRouter()\n"
        "svc = UserService()\n\n"
        "@router.get('/clean/{uid}')\n"
        "def clean_endpoint(uid: int):\n"
        "    return svc.get_user(uid)\n"
    )

    # API 2: Violating (bypasses Service to import UserRepository directly)
    (api_dir / "violating_routes.py").write_text(
        "from fastapi import APIRouter\n"
        "from repositories.user_repository import UserRepository\n\n"
        "router = APIRouter()\n"
        "raw_repo = UserRepository()\n\n"
        "@router.get('/violating/{uid}')\n"
        "def bad_endpoint(uid: int):\n"
        "    return raw_repo.query_user(uid)\n"
    )

    scan_id, findings, score = _scan_repo_api(repo, "Layer_Repo")
    violations = [f for f in findings if f["rule_id"] == "ENT-ARCH-002"]
    assert len(violations) >= 1
    assert any("violating_routes.py" in v["file"] for v in violations)


# ==============================================================================
# 5. God Module
# ==============================================================================


def test_5_god_module_detection_and_clean_large_module(tmp_path: Path):
    """Module combining 4+ orthogonal responsibilities is flagged; large single-domain file is not."""
    repo = tmp_path / "god_module_repo"
    repo.mkdir()

    # God module: combines Routing + Database + Auth + Config + System IO
    god_code = (
        "import os, subprocess, bcrypt\n"
        "from fastapi import APIRouter\n\n"
        "router = APIRouter()\n\n"
        "DATABASE_URL = os.environ.get('DATABASE_URL')\n\n"
        "def execute_db_query(sql):\n"
        "    return []\n\n"
        "def hash_password(pwd):\n"
        "    return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())\n\n"
        "def backup_database():\n"
        "    subprocess.run(['pg_dump', DATABASE_URL])\n\n"
        "@router.get('/everything')\n"
        "def handle_everything():\n"
        "    pwd = hash_password('secret')\n"
        "    execute_db_query('SELECT 1')\n"
        "    backup_database()\n"
        "    return {'status': 'ok'}\n"
    )
    # Pad to > 100 LOC
    god_code += "\n".join(f"def helper_{i}(): return {i}" for i in range(120)) + "\n"
    (repo / "monolith.py").write_text(god_code)

    # Legitimate single-domain large module (e.g. mathematical utility)
    clean_large_code = "class MathCalculator:\n" + "\n".join(
        f"    def compute_{i}(self, x: int) -> int:\n        return x * {i}\n" for i in range(100)
    )
    (repo / "math_calc.py").write_text(clean_large_code)

    scan_id, findings, score = _scan_repo_api(repo, "God_Module_Repo")
    god_findings = [f for f in findings if f["rule_id"] == "ENT-ARCH-005"]

    assert len(god_findings) >= 1
    assert any("monolith.py" in g["file"] for g in god_findings)
    assert not any("math_calc.py" in g["file"] for g in god_findings)


# ==============================================================================
# 6. God Class
# ==============================================================================


def test_6_god_class_detection(tmp_path: Path):
    """Class combining routing, database CRUD, and auth logic with 10+ methods triggers ENT-ARCH-006."""
    repo = tmp_path / "god_class_repo"
    repo.mkdir()

    god_class_code = (
        "class SuperManager:\n"
        "    def route_get_user(self): return {}\n"
        "    def route_post_user(self): return {}\n"
        "    def save_user_to_db(self): pass\n"
        "    def query_user_records(self): pass\n"
        "    def delete_user_record(self): pass\n"
        "    def commit_transaction(self): pass\n"
        "    def auth_verify_token(self): pass\n"
        "    def auth_hash_password(self): pass\n"
        "    def load_env_config(self): pass\n"
        "    def process_order_logic(self): pass\n"
        "    def calculate_tax(self): pass\n"
        "    def execute_step(self): pass\n"
    )
    (repo / "manager.py").write_text(god_class_code)

    scan_id, findings, score = _scan_repo_api(repo, "God_Class_Repo")
    class_findings = [f for f in findings if f["rule_id"] == "ENT-ARCH-006"]
    assert len(class_findings) >= 1
    assert "SuperManager" in class_findings[0]["title"]


# ==============================================================================
# 7. Configuration Inconsistency
# ==============================================================================


def test_7_configuration_inconsistency(tmp_path: Path):
    """Calling os.environ in an API module when centralized config exists triggers ENT-ARCH-004."""
    repo = tmp_path / "config_repo"
    repo.mkdir()

    # Centralized configuration
    cfg_dir = repo / "core"
    cfg_dir.mkdir()
    (cfg_dir / "config.py").write_text(
        "import os\n"
        "class Settings:\n"
        "    PORT = int(os.getenv('PORT', '8000'))\n"
        "    DB = os.getenv('DB', 'sqlite://')\n"
        "settings = Settings()\n"
    )

    # 3 peer modules using settings (establishing convention)
    (repo / "service_a.py").write_text("from core.config import settings\ndef get_port(): return settings.PORT\n")
    (repo / "service_b.py").write_text("from core.config import settings\ndef get_db(): return settings.DB\n")
    (repo / "service_c.py").write_text("from core.config import settings\ndef run(): return settings.PORT\n")

    # Inconsistent API module bypassing settings to use direct os.getenv
    api_dir = repo / "api"
    api_dir.mkdir()
    (api_dir / "routes.py").write_text(
        "import os\n"
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n\n"
        "@router.get('/status')\n"
        "def get_status():\n"
        "    host = os.getenv('APP_HOST', 'localhost')\n"
        "    return {'host': host}\n"
    )

    scan_id, findings, score = _scan_repo_api(repo, "Config_Repo")
    config_findings = [f for f in findings if f["rule_id"] == "ENT-ARCH-004"]
    assert len(config_findings) >= 1
    assert any("routes.py" in c["file"] for c in config_findings)


# ==============================================================================
# 8. Excessive Cross-Layer Coupling
# ==============================================================================


def test_8_cross_layer_coupling(tmp_path: Path):
    """Module directly importing from 4+ distinct layers triggers ENT-ARCH-007."""
    repo = tmp_path / "coupling_repo"
    repo.mkdir()

    # Layers
    (repo / "models").mkdir()
    (repo / "models" / "dto.py").write_text("class DTO: pass\n")

    (repo / "services").mkdir()
    (repo / "services" / "biz.py").write_text("class Biz: pass\n")

    (repo / "repositories").mkdir()
    (repo / "repositories" / "store.py").write_text("class Store: pass\n")

    (repo / "security").mkdir()
    (repo / "security" / "token.py").write_text("class Token: pass\n")

    (repo / "config").mkdir()
    (repo / "config" / "cfg.py").write_text("class Config: pass\n")

    # API module directly coupled to all 5 layers
    (repo / "api").mkdir()
    (repo / "api" / "tangled.py").write_text(
        "from fastapi import APIRouter\n"
        "from models.dto import DTO\n"
        "from services.biz import Biz\n"
        "from repositories.store import Store\n"
        "from security.token import Token\n"
        "from config.cfg import Config\n\n"
        "router = APIRouter()\n"
        "@router.get('/all')\ndef handle(): return {}\n"
    )

    scan_id, findings, score = _scan_repo_api(repo, "Coupling_Repo")
    coupling_findings = [f for f in findings if f["rule_id"] == "ENT-ARCH-007"]
    assert len(coupling_findings) >= 1
    assert "tangled.py" in coupling_findings[0]["file"]


# ==============================================================================
# 9. Inconsistent Architectural Pattern
# ==============================================================================


def test_9_inconsistent_architectural_pattern(tmp_path: Path):
    """Route module diverging from dominant Route -> Service pattern triggers ENT-ARCH-008."""
    repo = tmp_path / "pattern_repo"
    repo.mkdir()

    (repo / "services").mkdir()
    (repo / "services" / "user_svc.py").write_text("def get_user(): return {}\n")

    api_dir = repo / "api"
    api_dir.mkdir()

    # 3 modules following Route -> Service
    (api_dir / "route_1.py").write_text(
        "from fastapi import APIRouter\nfrom services.user_svc import get_user\n"
        "router = APIRouter()\n@router.get('/1')\ndef h1(): return get_user()\n"
    )
    (api_dir / "route_2.py").write_text(
        "from fastapi import APIRouter\nfrom services.user_svc import get_user\n"
        "router = APIRouter()\n@router.get('/2')\ndef h2(): return get_user()\n"
    )
    (api_dir / "route_3.py").write_text(
        "from fastapi import APIRouter\nfrom services.user_svc import get_user\n"
        "router = APIRouter()\n@router.get('/3')\ndef h3(): return get_user()\n"
    )

    # 1 outlier doing direct raw SQL execution
    (api_dir / "route_outlier.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/outlier')\n"
        "def bad():\n"
        "    raw_sql = 'SELECT * FROM users'\n"
        "    return raw_sql\n"
    )

    scan_id, findings, score = _scan_repo_api(repo, "Pattern_Repo")
    pattern_findings = [f for f in findings if f["rule_id"] == "ENT-ARCH-008"]
    assert len(pattern_findings) >= 1
    assert "route_outlier.py" in pattern_findings[0]["file"]


# ==============================================================================
# 10. Excluded Files Ignored
# ==============================================================================


def test_10_excluded_paths_ignored(tmp_path: Path):
    """Files in tests/, fixtures/, migrations/ do not generate architectural findings."""
    repo = tmp_path / "excluded_repo"
    repo.mkdir()

    test_dir = repo / "tests"
    test_dir.mkdir()
    # Cycle inside tests directory should be completely ignored
    (test_dir / "test_a.py").write_text("import test_b\n")
    (test_dir / "test_b.py").write_text("import test_a\n")

    scan_id, findings, score = _scan_repo_api(repo, "Excluded_Repo")
    arch_findings = [f for f in findings if f["category"] == "architectural_consistency"]
    assert len(arch_findings) == 0


# ==============================================================================
# 11. Determinism
# ==============================================================================


def test_11_determinism_across_scans(tmp_path: Path):
    """Two identical scans produce 100% identical findings, IDs, fingerprints, and scores."""
    repo = tmp_path / "det_repo"
    repo.mkdir()

    (repo / "a.py").write_text("import b\ndef fa(): return b.fb()\n")
    (repo / "b.py").write_text("import a\ndef fb(): return a.fa()\n")

    scan_id1, findings1, score1 = _scan_repo_api(repo, "Scan1")
    scan_id2, findings2, score2 = _scan_repo_api(repo, "Scan2")

    assert len(findings1) == len(findings2)
    assert score1["total_score"] == score2["total_score"]
    assert score1["tier"] == score2["tier"]

    for f1, f2 in zip(findings1, findings2, strict=True):
        assert f1["id"] == f2["id"]
        assert f1["fingerprint"] == f2["fingerprint"]
        assert f1["rule_id"] == f2["rule_id"]
        assert f1["severity"] == f2["severity"]
        assert f1["file"] == f2["file"]
        assert f1["line_start"] == f2["line_start"]


# ==============================================================================
# 12. Remediation Lifecycle
# ==============================================================================


def test_12_remediation_reduces_score(tmp_path: Path):
    """Fixing architectural debt reduces category and total score to 0; restoring brings it back."""
    repo = tmp_path / "remediation_repo"
    repo.mkdir()

    # Step 1: Bad architecture with circular dependency
    (repo / "a.py").write_text("import b\ndef fa(): return b.fb()\n")
    (repo / "b.py").write_text("import a\ndef fb(): return a.fa()\n")

    _, findings_bad, score_bad = _scan_repo_api(repo, "Bad_Arch")
    assert len([f for f in findings_bad if f["rule_id"] == "ENT-ARCH-001"]) == 1
    assert score_bad["category_scores"]["architectural_consistency"]["score"] > 0
    bad_total = score_bad["total_score"]

    # Step 2: Fix by breaking the cycle
    (repo / "b.py").write_text("def fb(): return 'clean'\n")

    _, findings_fixed, score_fixed = _scan_repo_api(repo, "Fixed_Arch")
    assert len([f for f in findings_fixed if f["rule_id"] == "ENT-ARCH-001"]) == 0
    assert score_fixed["category_scores"]["architectural_consistency"]["score"] == 0.0
    assert score_fixed["total_score"] <= bad_total

    # Step 3: Restore the cycle
    (repo / "b.py").write_text("import a\ndef fb(): return a.fa()\n")

    _, findings_restored, score_restored = _scan_repo_api(repo, "Restored_Arch")
    assert len([f for f in findings_restored if f["rule_id"] == "ENT-ARCH-001"]) == 1
    assert score_restored["total_score"] == bad_total


# ==============================================================================
# 13. Malicious Canary Zero Code Execution
# ==============================================================================


def test_13_malicious_canary_zero_code_execution(tmp_path: Path):
    """Repository containing dangerous code is never executed during architecture analysis."""
    repo = tmp_path / "malicious_repo"
    repo.mkdir()

    canary = tmp_path / "ENTROPY_WAS_HACKED.txt"
    if canary.exists():
        canary.unlink()

    malicious_code = (
        "from pathlib import Path\n\n"
        f"Path({str(canary)!r}).write_text('EXECUTED')\n\n"
        "def harmless():\n"
        "    return True\n"
    )
    (repo / "exploit.py").write_text(malicious_code)

    scan_id, findings, score = _scan_repo_api(repo, "Malicious_Repo")

    # Invariant: canary was NEVER touched
    assert not canary.exists(), "SECURITY INVARIANT VIOLATED: Target repository code was executed!"


# ==============================================================================
# 14. Application Composition Root Precision
# ==============================================================================


def test_14_composition_root_not_flagged_for_cross_layer_coupling(tmp_path: Path):
    """An application composition root / entry point wiring 4+ layers is not flagged for ENT-ARCH-007."""
    repo = tmp_path / "composition_root_repo"
    repo.mkdir()

    # Define 4 distinct layers
    (repo / "models").mkdir()
    (repo / "models" / "item.py").write_text("class Item: pass\n")

    (repo / "services").mkdir()
    (repo / "services" / "item_service.py").write_text("class ItemService: pass\n")

    (repo / "repositories").mkdir()
    (repo / "repositories" / "item_repo.py").write_text("class ItemRepository: pass\n")

    (repo / "config").mkdir()
    (repo / "config" / "settings.py").write_text("class Settings: pass\n")

    (repo / "api").mkdir()
    (repo / "api" / "routes.py").write_text("from fastapi import APIRouter\nrouter = APIRouter()\n")

    # Application Composition Root: instantiates FastAPI and wires layers together
    bootstrap_code = (
        "from fastapi import FastAPI\n"
        "from config.settings import Settings\n"
        "from api.routes import router\n"
        "from services.item_service import ItemService\n"
        "from repositories.item_repo import ItemRepository\n"
        "from models.item import Item\n\n"
        "app = FastAPI(title='App')\n"
        "app.include_router(router)\n"
        "settings = Settings()\n"
        "service = ItemService()\n"
    )
    (repo / "main.py").write_text(bootstrap_code)

    scan_id, findings, score = _scan_repo_api(repo, "Composition_Root_Repo")
    coupling_findings = [f for f in findings if f["rule_id"] == "ENT-ARCH-007"]

    # Invariant: Composition root is NOT flagged for cross-layer coupling
    assert not any("main.py" in f["file"] for f in coupling_findings), (
        f"Composition root was falsely flagged for cross-layer coupling: {coupling_findings}"
    )


# ==============================================================================
# 15. Analyzer Heuristic Keywords Precision
# ==============================================================================


def test_15_rule_heuristics_analyzer_not_flagged_as_god_module(tmp_path: Path):
    """A module defining static analysis inspection rules/keywords is not falsely flagged as a God Module."""
    repo = tmp_path / "analyzer_repo"
    repo.mkdir()

    # An analyzer module that contains heuristic token strings in tuples/constants,
    # but does NOT call them or perform multi-domain operations.
    rule_module_code = (
        "'''Static analysis inspection rules.'''\n"
        "AUTH_KEYWORDS = ('jwt', 'bcrypt', 'hash_password', 'verify_password', 'token_url')\n"
        "CONFIG_CHECKS = ('os.environ', 'os.getenv', 'BaseSettings')\n"
        "IO_CALLS = ('subprocess.run', 'subprocess.Popen', 'os.system', 'open(')\n\n"
        "class RuleInspector:\n"
        "    def inspect_tokens(self, tokens: list[str]) -> list[str]:\n"
        "        matched = []\n"
        "        for t in tokens:\n"
        "            if t in AUTH_KEYWORDS or t in CONFIG_CHECKS or t in IO_CALLS:\n"
        "                matched.append(t)\n"
        "        return matched\n"
    )
    # Pad to > 100 LOC with clean inspector methods
    rule_module_code += "\n".join(
        f"    def check_pattern_{i}(self, s: str) -> bool:\n        return str({i}) in s\n"
        for i in range(120)
    )
    (repo / "rule_inspector.py").write_text(rule_module_code)

    scan_id, findings, score = _scan_repo_api(repo, "Analyzer_Repo")
    god_findings = [f for f in findings if f["rule_id"] == "ENT-ARCH-005"]

    # Invariant: Rule inspector is NOT falsely identified as having 4+ orthogonal responsibilities
    assert not any("rule_inspector.py" in f["file"] for f in god_findings), (
        f"Rule inspector module was falsely flagged as God Module: {god_findings}"
    )

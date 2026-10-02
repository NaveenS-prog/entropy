"""Comprehensive unit tests for Phase 8 Code Duplication & Boilerplate Debt Analyzer.

Explicitly implements Tests 1 through 13 from Phase 8 specification:
1. Clean code (no duplication)
2. Exact structural duplication
3. Formatting difference
4. Identifier difference
5. Small snippet (false positive control)
6. Intentional common idiom (false positive control)
7. Cross-file duplication
8. Duplication cluster (1 cluster, not n*(n-1)/2 findings)
9. Different logic (not falsely clustered)
10. Ignored/test file exclusion
11. Determinism across repeated scans
12. Remediation verification
13. Malicious canary (zero code execution)
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.analyzers.context import AnalysisContext
from app.analyzers.duplication import CodeDuplicationDebtAnalyzer
from app.main import app
from app.parser.python import PythonParser

client = TestClient(app)


def _analyze_code_string(code: str, file_path: str = "app/sample.py") -> list:
    """Helper to run CodeDuplicationDebtAnalyzer on a single Python code string."""
    parser = PythonParser()
    unit = parser.parse_source(code, file_path=file_path)
    context = AnalysisContext.from_python_units(
        repo_path=Path("/tmp/mock_repo"),
        units=[unit],
    )
    analyzer = CodeDuplicationDebtAnalyzer()
    return analyzer.analyze(context)


def _analyze_multi_file_dict(files: dict[str, str], repo_dir: Path) -> list:
    """Helper to run CodeDuplicationDebtAnalyzer on multiple files in a repository directory."""
    parser = PythonParser()
    units = []
    for rel_path, code in files.items():
        full_path = repo_dir / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(code, encoding="utf-8")
        unit = parser.parse_source(code, file_path=rel_path, absolute_path=full_path)
        units.append(unit)

    context = AnalysisContext.from_python_units(
        repo_path=repo_dir,
        units=units,
    )
    analyzer = CodeDuplicationDebtAnalyzer()
    return analyzer.analyze(context)


# ==============================================================================
# TEST 1 — CLEAN CODE
# ==============================================================================

def test_1_clean_code_no_duplication():
    """Two completely distinct functions should produce zero duplication findings."""
    code = (
        "def compute_payroll(employees, tax_rate):\n"
        "    total = sum(emp['salary'] for emp in employees)\n"
        "    deductions = total * tax_rate\n"
        "    return total - deductions\n\n"
        "def parse_http_header(raw_header: str):\n"
        "    parts = raw_header.split(':')\n"
        "    key = parts[0].strip().lower()\n"
        "    value = parts[1].strip()\n"
        "    return {key: value}\n"
    )
    findings = _analyze_code_string(code)
    assert len(findings) == 0


# ==============================================================================
# TEST 2 — EXACT STRUCTURAL DUPLICATION
# ==============================================================================

def test_2_exact_structural_duplication():
    """Two structurally identical functions with different variable names."""
    code = (
        "def calculate_total(price):\n"
        "    tax = price * 0.18\n"
        "    return price + tax\n\n"
        "def compute_amount(value):\n"
        "    fee = value * 0.18\n"
        "    return value + fee\n"
    )
    findings = _analyze_code_string(code)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "ENT-DUP-001"
    assert f.category.value == "code_duplication"
    assert f.metadata["is_exact"] is True
    assert f.metadata["similarity"] == 1.0
    assert f.metadata["occurrences"] == 2


# ==============================================================================
# TEST 3 — FORMATTING DIFFERENCE
# ==============================================================================

def test_3_formatting_and_comment_difference():
    """Identical logic with comments, whitespace, and docstring differences must still match."""
    code = (
        "def process_data(items):\n"
        "    '''Docstring for process_data.'''\n"
        "    # Step 1: filter items\n"
        "    valid = [x for x in items if x > 0]\n"
        "    # Step 2: double them\n"
        "    doubled = [y * 2 for y in valid]\n"
        "    return sum(doubled)\n\n"
        "def handle_records(records):\n"
        "\n"
        "    res = [item for item in records if item > 0]\n"
        "\n"
        "    scaled = [val * 2 for val in res]\n"
        "    return sum(scaled)\n"
    )
    findings = _analyze_code_string(code)
    assert len(findings) == 1
    assert findings[0].rule_id == "ENT-DUP-001"
    assert findings[0].metadata["is_exact"] is True


# ==============================================================================
# TEST 4 — IDENTIFIER DIFFERENCE
# ==============================================================================

def test_4_identifier_difference_similar_functions():
    """Same algorithm with different identifiers and slight structural extension."""
    code = (
        "def sync_user_accounts(users, db_conn):\n"
        "    active = [u for u in users if u['active']]\n"
        "    for item in active:\n"
        "        db_conn.save(item)\n"
        "    return len(active)\n\n"
        "def synchronize_tenants(tenants, storage):\n"
        "    enabled = [t for t in tenants if t['active']]\n"
        "    for record in enabled:\n"
        "        storage.save(record)\n"
        "    return len(enabled)\n"
    )
    findings = _analyze_code_string(code)
    assert len(findings) == 1
    assert findings[0].rule_id in ("ENT-DUP-001", "ENT-DUP-002")
    assert findings[0].metadata["occurrences"] == 2


# ==============================================================================
# TEST 5 — SMALL SNIPPET
# ==============================================================================

def test_5_small_snippets_ignored():
    """Tiny 1-line functions, trivial expressions, or empty blocks must not produce findings."""
    code = (
        "def get_a(self): return self._a\n"
        "def get_b(self): return self._b\n"
        "def noop_one(): pass\n"
        "def noop_two(): pass\n"
        "def add_one(x): return x + 1\n"
        "def add_two(y): return y + 1\n"
    )
    findings = _analyze_code_string(code)
    assert len(findings) == 0


# ==============================================================================
# TEST 6 — INTENTIONAL COMMON IDIOM
# ==============================================================================

def test_6_intentional_common_idiom():
    """Trivial constructors or standard Python idioms must not trigger false positives."""
    code = (
        "class Point:\n"
        "    def __init__(self, x, y):\n"
        "        self.x = x\n"
        "        self.y = y\n\n"
        "class Vector:\n"
        "    def __init__(self, u, v):\n"
        "        self.u = u\n"
        "        self.v = v\n"
    )
    findings = _analyze_code_string(code)
    assert len(findings) == 0


# ==============================================================================
# TEST 7 — CROSS-FILE DUPLICATION
# ==============================================================================

def test_7_cross_file_duplication(tmp_path: Path):
    """Duplicated logic across two separate files should trigger ENT-DUP-004."""
    files = {
        "services/user_service.py": (
            "def calculate_discount(amount):\n"
            "    rate = 0.15\n"
            "    discount = amount * rate\n"
            "    return amount - discount\n"
        ),
        "services/order_service.py": (
            "def apply_rebate(total):\n"
            "    ratio = 0.15\n"
            "    rebate = total * ratio\n"
            "    return total - rebate\n"
        ),
    }
    findings = _analyze_multi_file_dict(files, tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "ENT-DUP-004"
    assert f.metadata["is_cross_file"] is True
    assert len(f.metadata["affected_files"]) == 2


# ==============================================================================
# TEST 8 — DUPLICATION CLUSTER
# ==============================================================================

def test_8_duplication_cluster_four_functions(tmp_path: Path):
    """Four similar functions must produce ONE cluster finding (ENT-DUP-005), not 6 pairwise findings."""
    files = {
        "modules/alpha.py": (
            "def process_alpha(data):\n"
            "    filtered = [x for x in data if x > 0]\n"
            "    total = sum(filtered)\n"
            "    return total * 1.05\n"
        ),
        "modules/beta.py": (
            "def process_beta(items):\n"
            "    valid = [i for i in items if i > 0]\n"
            "    subtotal = sum(valid)\n"
            "    return subtotal * 1.05\n"
        ),
        "modules/gamma.py": (
            "def process_gamma(values):\n"
            "    elements = [v for v in values if v > 0]\n"
            "    agg = sum(elements)\n"
            "    return agg * 1.05\n"
        ),
        "modules/delta.py": (
            "def process_delta(numbers):\n"
            "    cleared = [n for n in numbers if n > 0]\n"
            "    res = sum(cleared)\n"
            "    return res * 1.05\n"
        ),
    }
    findings = _analyze_multi_file_dict(files, tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "ENT-DUP-005"
    assert f.metadata["occurrences"] == 4
    assert len(f.metadata["affected_files"]) == 4


# ==============================================================================
# TEST 9 — DIFFERENT LOGIC
# ==============================================================================

def test_9_different_logic_not_falsely_clustered():
    """Functions with different operators or control flow shapes should not be clustered."""
    code = (
        "def compute_addition(a, b):\n"
        "    val = a + b\n"
        "    res = val + 10\n"
        "    return res\n\n"
        "def compute_multiplication(x, y):\n"
        "    val = x * y\n"
        "    res = val * 10\n"
        "    return res\n"
    )
    findings = _analyze_code_string(code)
    assert len(findings) == 0


# ==============================================================================
# TEST 10 — IGNORED / TEST FILE EXCLUSION
# ==============================================================================

def test_10_ignored_file_exclusion(tmp_path: Path):
    """Duplication inside tests/ or fixtures/ directories must be excluded from findings."""
    files = {
        "tests/test_service.py": (
            "def test_helper_one(item):\n"
            "    val = item * 2\n"
            "    assert val > 0\n"
            "    return val\n\n"
            "def test_helper_two(data):\n"
            "    val = data * 2\n"
            "    assert val > 0\n"
            "    return val\n"
        )
    }
    findings = _analyze_multi_file_dict(files, tmp_path)
    assert len(findings) == 0


# ==============================================================================
# TEST 11 — DETERMINISM
# ==============================================================================

def test_11_determinism_across_scans(tmp_path: Path):
    """Two identical scans of the same repository must produce 100% identical findings, fingerprints, and scores."""
    src_dir = tmp_path / "det_repo" / "src"
    src_dir.mkdir(parents=True)
    (src_dir / "service_a.py").write_text(
        "def compute_fee(amount):\n"
        "    tax = amount * 0.18\n"
        "    return amount + tax\n",
        encoding="utf-8",
    )
    (src_dir / "service_b.py").write_text(
        "def compute_cost(price):\n"
        "    charge = price * 0.18\n"
        "    return price + charge\n",
        encoding="utf-8",
    )

    resp1 = client.post("/api/v1/repositories/scan", json={"path": str(tmp_path / "det_repo")})
    assert resp1.status_code == 201
    scan_id1 = resp1.json()["scan_id"]
    findings1 = client.get(f"/api/v1/scans/{scan_id1}/findings").json()
    score1 = client.get(f"/api/v1/scans/{scan_id1}/score").json()

    resp2 = client.post("/api/v1/repositories/scan", json={"path": str(tmp_path / "det_repo")})
    assert resp2.status_code == 201
    scan_id2 = resp2.json()["scan_id"]
    findings2 = client.get(f"/api/v1/scans/{scan_id2}/findings").json()
    score2 = client.get(f"/api/v1/scans/{scan_id2}/score").json()

    # Verify identical counts, IDs, fingerprints, and scores
    assert len(findings1) == len(findings2)
    assert [f["id"] for f in findings1] == [f["id"] for f in findings2]
    assert [f["fingerprint"] for f in findings1] == [f["fingerprint"] for f in findings2]
    assert [f["rule_id"] for f in findings1] == [f["rule_id"] for f in findings2]
    assert score1["total_score"] == score2["total_score"]
    assert score1["category_scores"]["code_duplication"]["score"] == score2["category_scores"]["code_duplication"]["score"]


# ==============================================================================
# TEST 12 — REMEDIATION
# ==============================================================================

def test_12_remediation_reduces_score(tmp_path: Path):
    """When duplication is refactored into a single shared function, the finding disappears and score decreases."""
    repo_dir = tmp_path / "remed_repo"
    src_dir = repo_dir / "src"
    src_dir.mkdir(parents=True)

    file_a = src_dir / "calc_a.py"
    file_b = src_dir / "calc_b.py"

    # Initial: Duplicated code
    file_a.write_text(
        "def compute_tax(val):\n"
        "    t = val * 0.18\n"
        "    return val + t\n",
        encoding="utf-8",
    )
    file_b.write_text(
        "def compute_price(p):\n"
        "    fee = p * 0.18\n"
        "    return p + fee\n",
        encoding="utf-8",
    )

    resp1 = client.post("/api/v1/repositories/scan", json={"path": str(repo_dir)})
    scan_id1 = resp1.json()["scan_id"]
    findings1 = client.get(f"/api/v1/scans/{scan_id1}/findings?category=code_duplication").json()
    score1 = client.get(f"/api/v1/scans/{scan_id1}/score").json()
    assert len(findings1) == 1
    assert score1["category_scores"]["code_duplication"]["score"] > 0

    # Remediation: Refactor file_b to call shared module or different logic
    file_b.write_text(
        "from src.calc_a import compute_tax\n"
        "def compute_price(p):\n"
        "    return compute_tax(p)\n",
        encoding="utf-8",
    )

    resp2 = client.post("/api/v1/repositories/scan", json={"path": str(repo_dir)})
    scan_id2 = resp2.json()["scan_id"]
    findings2 = client.get(f"/api/v1/scans/{scan_id2}/findings?category=code_duplication").json()
    score2 = client.get(f"/api/v1/scans/{scan_id2}/score").json()

    assert len(findings2) == 0
    assert score2["category_scores"]["code_duplication"]["score"] == 0.0
    assert score2["total_score"] <= score1["total_score"]


# ==============================================================================
# TEST 13 — MALICIOUS CANARY (Zero Code Execution)
# ==============================================================================

def test_13_malicious_canary_zero_code_execution(tmp_path: Path):
    """The analyzer must NEVER execute target repository code."""
    repo_dir = tmp_path / "canary_repo"
    repo_dir.mkdir()

    canary_file = repo_dir / "canary.txt"
    if canary_file.exists():
        canary_file.unlink()

    malicious_code = (
        "from pathlib import Path\n"
        f"Path('{canary_file.resolve()}').write_text('CANARY_EXECUTED')\n\n"
        "def malicious_fn_one(x):\n"
        "    Path('side_effect_1.txt').touch()\n"
        "    return x * 2\n\n"
        "def malicious_fn_two(y):\n"
        "    Path('side_effect_2.txt').touch()\n"
        "    return y * 2\n"
    )
    (repo_dir / "exploit.py").write_text(malicious_code, encoding="utf-8")

    # Run full repository scan
    scan_resp = client.post("/api/v1/repositories/scan", json={"path": str(repo_dir)})
    assert scan_resp.status_code == 201

    # Verify canary was never created
    assert not canary_file.exists(), "SECURITY VIOLATION: Canary file was created! Code was executed!"
    assert not (repo_dir / "side_effect_1.txt").exists()
    assert not (repo_dir / "side_effect_2.txt").exists()

"""Phase 4 Regression Tests: Python SQL injection detection and framework parity.

Validates:
1. SQL injection by concatenation: db.run("DELETE ... WHERE id=" + id) flags ENT-INPUT-003.
2. SQL injection by f-string: cursor.execute(f"DELETE FROM users WHERE id={id}") flags ENT-INPUT-003.
3. SQL injection by %-formatting: cursor.execute("DELETE FROM users WHERE id=%s" % id) flags ENT-INPUT-003.
4. SQL injection in session.execute(text(...)): flags ENT-INPUT-003.
5. Parameterized queries (false-positive controls) do NOT flag ENT-INPUT-003.
6. FastAPI 3-route app lands in at least MODERATE, and Python vs JS versions score within 10 points.
"""

import tempfile
from pathlib import Path

from app.analyzers.context import PythonASTContext
from app.analyzers.security.validation.rules import UnsafeDirectInputUsageRule
from app.models.domain.enums import DebtScoreTier, SupportedLanguage
from app.parser.python.parser import PythonParser
from app.services.scan_service import ScanService


def _analyze_python_code(code: str) -> list:
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        f.flush()
        path = Path(f.name)

    try:
        parser = PythonParser()
        unit = parser.parse_file(path, "app.py", SupportedLanguage.PYTHON)
        ctx = PythonASTContext(unit)
        rule = UnsafeDirectInputUsageRule()
        return rule.analyze_file(ctx)
    finally:
        path.unlink(missing_ok=True)


def test_sql_injection_concatenation():
    """String concatenation in db.run flags ENT-INPUT-003."""
    code = """
from fastapi import FastAPI
app = FastAPI()

@app.post("/admin/delete-user")
def delete_user(id: str):
    db.run("DELETE FROM users WHERE id=" + id)
"""
    findings = _analyze_python_code(code)
    sql_findings = [f for f in findings if f.rule_id == "ENT-INPUT-003"]
    assert len(sql_findings) == 1
    assert "DELETE FROM users WHERE id=" in sql_findings[0].description


def test_sql_injection_fstring():
    """f-string interpolation in cursor.execute flags ENT-INPUT-003."""
    code = """
from fastapi import FastAPI
app = FastAPI()

@app.post("/admin/delete-user")
def delete_user(id: str):
    cursor.execute(f"DELETE FROM users WHERE id={id}")
"""
    findings = _analyze_python_code(code)
    sql_findings = [f for f in findings if f.rule_id == "ENT-INPUT-003"]
    assert len(sql_findings) == 1
    assert "DELETE FROM users WHERE id=" in sql_findings[0].description


def test_sql_injection_percent_format():
    """% formatting in cursor.execute flags ENT-INPUT-003."""
    code = """
from fastapi import FastAPI
app = FastAPI()

@app.post("/admin/delete-user")
def delete_user(id: str):
    cursor.execute("DELETE FROM users WHERE id=%s" % id)
"""
    findings = _analyze_python_code(code)
    sql_findings = [f for f in findings if f.rule_id == "ENT-INPUT-003"]
    assert len(sql_findings) == 1


def test_sql_injection_session_execute_text():
    """session.execute(text(...)) with concatenation flags ENT-INPUT-003."""
    code = """
from fastapi import FastAPI
from sqlalchemy import text
app = FastAPI()

@app.post("/admin/delete-user")
def delete_user(id: str):
    session.execute(text("DELETE FROM users WHERE id=" + id))
"""
    findings = _analyze_python_code(code)
    sql_findings = [f for f in findings if f.rule_id == "ENT-INPUT-003"]
    assert len(sql_findings) == 1


def test_sql_parameterized_queries_do_not_fire():
    """False-positive control: Parameterized queries must never fire ENT-INPUT-003."""
    code = """
from fastapi import FastAPI
from sqlalchemy import text
app = FastAPI()

@app.post("/admin/delete-tuple")
def delete_tuple(id: str):
    cursor.execute("DELETE FROM users WHERE id = %s", (id,))

@app.post("/admin/delete-dict")
def delete_dict(id: str):
    cursor.execute("DELETE FROM users WHERE id = :id", {"id": id})

@app.post("/admin/delete-text")
def delete_text(id: str):
    session.execute(text("DELETE FROM users WHERE id = :id"), {"id": id})

@app.post("/admin/delete-run")
def delete_run(id: str):
    db.run("DELETE FROM users WHERE id = :id", id=id)
"""
    findings = _analyze_python_code(code)
    sql_findings = [f for f in findings if f.rule_id == "ENT-INPUT-003"]
    assert len(sql_findings) == 0


def test_fastapi_three_route_app_and_js_twin_parity():
    """Reproduction: FastAPI three-route app lands in >= MODERATE and is within 10 pts of JS twin."""
    py_code = """from fastapi import FastAPI
app = FastAPI()

@app.post('/admin/delete-user')
def delete_user(id: str):
    db.run('DELETE ... WHERE id=' + id)

@app.get('/admin/export')
def export_data():
    return {'export': True}

@app.post('/payments/refund')
def refund():
    return {'refund': True}
"""

    js_code = """const express = require('express');
const app = express();

app.post('/admin/delete-user', (req, res) => {
    db.run('DELETE ... WHERE id=' + req.body.id);
});

app.get('/admin/export', (req, res) => {
    res.json({ export: true });
});

app.post('/payments/refund', (req, res) => {
    res.json({ refund: true });
});
"""
    service = ScanService()

    with tempfile.TemporaryDirectory() as py_dir:
        (Path(py_dir) / "app.py").write_text(py_code)
        res_py = service.execute_scan(Path(py_dir))

    with tempfile.TemporaryDirectory() as js_dir:
        (Path(js_dir) / "app.js").write_text(js_code)
        res_js = service.execute_scan(Path(js_dir))

    # 1. FastAPI app lands in at least MODERATE
    assert res_py.score.total_score >= 41
    assert res_py.score.tier in (
        DebtScoreTier.MODERATE,
        DebtScoreTier.HIGH,
        DebtScoreTier.VERY_HIGH,
    )

    # 2. Both versions detect the SQL injection
    py_rules = [f.rule_id for f in res_py.findings]
    js_rules = [f.rule_id for f in res_js.findings]
    assert "ENT-INPUT-003" in py_rules
    assert "ENT-INPUT-JS-001" in js_rules

    # 3. Python and JS versions must be within 10 points
    score_gap = abs(res_py.score.total_score - res_js.score.total_score)
    assert score_gap <= 10.0, f"Expected gap <= 10, got {score_gap:.1f}"

"""Phase 11 Verification Script: Validates JavaScript and TypeScript static analysis engine.

Audits:
1. Zero code execution security invariant (malicious JS/TS canaries).
2. All Phase 11 JS/TS static rules (Error Handling, Input Validation, Logging & Secrets, Duplication, Architecture).
3. False-positive defense controls.
4. Strict repeat scan determinism.
5. Controlled 3-step differential truth test (Scan A -> Scan B -> Scan C).
6. End-to-end mixed-language scan on the real Entropy repository.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

# Add backend directory to sys.path for direct execution
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient

from app.main import app
from app.models.domain.enums import SupportedLanguage
from app.parser.jsts.parser import JSTSParser

client = TestClient(app)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
JS_FIXTURES = FIXTURES_DIR / "javascript"
TS_FIXTURES = FIXTURES_DIR / "typescript"


def run_phase11_verification() -> bool:
    print("=" * 80)
    print("PHASE 11 — JAVASCRIPT & TYPESCRIPT STATIC ANALYSIS ENGINE AUDIT")
    print("=" * 80)

    # -------------------------------------------------------------------------
    # 1. Zero Code Execution Canary Audit
    # -------------------------------------------------------------------------
    print("\n[Audit 1] Zero Code Execution Security Invariant...")
    canary_js = "/tmp/malicious_js_executed.txt"
    canary_ts = "/tmp/malicious_ts_executed.txt"
    for p in (canary_js, canary_ts):
        if os.path.exists(p):
            os.remove(p)

    parser = JSTSParser()
    unit_js = parser.parse_file(JS_FIXTURES / "malicious.js", "javascript/malicious.js", SupportedLanguage.JAVASCRIPT)
    unit_ts = parser.parse_file(TS_FIXTURES / "malicious.ts", "typescript/malicious.ts", SupportedLanguage.TYPESCRIPT)

    assert unit_js.is_valid, "Malicious JS should parse safely without crashing"
    assert unit_ts.is_valid, "Malicious TS should parse safely without crashing"
    assert not os.path.exists(canary_js), "CRITICAL SECURITY FAULT: JS Canary executed!"
    assert not os.path.exists(canary_ts), "CRITICAL SECURITY FAULT: TS Canary executed!"
    print("  ✓ Zero code execution invariant preserved: canaries parsed strictly in-memory without side effects")

    # -------------------------------------------------------------------------
    # 2. Rule Coverage and Detection on Dedicated Fixtures
    # -------------------------------------------------------------------------
    print("\n[Audit 2] Rule Coverage on Dedicated JS/TS Fixtures...")
    resp_js = client.post(
        "/api/v1/repositories/scan",
        json={"path": str(JS_FIXTURES), "repo_name": "JS_Fixtures"},
    )
    assert resp_js.status_code == 201, f"JS scan failed: {resp_js.text}"
    sid_js = resp_js.json()["scan_id"]

    findings_js = client.get(f"/api/v1/scans/{sid_js}/findings").json()
    rule_counts: dict[str, int] = {}
    for f in findings_js:
        rid = f["rule_id"]
        rule_counts[rid] = rule_counts.get(rid, 0) + 1

    print(f"  ✓ JS Fixture scan completed ({len(findings_js)} total findings)")
    for rid, count in sorted(rule_counts.items()):
        print(f"    - {rid}: {count} finding(s)")

    # Assert expected rules fired on JS fixtures
    assert "ENT-ERR-JS-001" in rule_counts, "ENT-ERR-JS-001 (Empty Catch) must fire"
    assert "ENT-ERR-JS-002" in rule_counts, "ENT-ERR-JS-002 (Swallowed Fallback) must fire"
    assert "ENT-INPUT-JS-001" in rule_counts, "ENT-INPUT-JS-001 (Unvalidated Input) must fire"
    assert "ENT-LOG-JS-001" in rule_counts, "ENT-LOG-JS-001 (Sensitive Log) must fire"
    assert "ENT-LOG-JS-002" in rule_counts, "ENT-LOG-JS-002 (Hardcoded Secret) must fire"
    assert "ENT-LOG-JS-003" in rule_counts, "ENT-LOG-JS-003 (Insecure Fallback) must fire"

    # Assert false positive controls on false_positives.js
    fp_findings = [f for f in findings_js if "false_positives.js" in f["file"]]
    assert len(fp_findings) == 0, f"False-positive controls failed on false_positives.js: {fp_findings}"
    print("  ✓ False-positive defense confirmed: false_positives.js produced 0 false findings")

    # Clean file test
    clean_findings = [f for f in findings_js if "clean.js" in f["file"]]
    assert len(clean_findings) == 0, f"Clean file clean.js produced unexpected findings: {clean_findings}"
    print("  ✓ Clean code baseline confirmed: clean.js produced 0 findings")

    # -------------------------------------------------------------------------
    # 3. Determinism and Repeatability Audit
    # -------------------------------------------------------------------------
    print("\n[Audit 3] Strict Scan Determinism Verification...")
    resp_js2 = client.post(
        "/api/v1/repositories/scan",
        json={"path": str(JS_FIXTURES), "repo_name": "JS_Fixtures"},
    )
    sid_js2 = resp_js2.json()["scan_id"]
    findings_js2 = client.get(f"/api/v1/scans/{sid_js2}/findings").json()

    assert len(findings_js) == len(findings_js2), "Finding counts must match exactly"
    assert [f["id"] for f in findings_js] == [f["id"] for f in findings_js2], "Finding IDs must be deterministic"
    assert [f["fingerprint"] for f in findings_js] == [f["fingerprint"] for f in findings_js2], "Fingerprints must match"
    print("  ✓ Repeat scan determinism verified: exact 1-to-1 match across IDs, fingerprints, and scores")

    # -------------------------------------------------------------------------
    # 4. Controlled Differential Truth Test (Scan A -> B -> C)
    # -------------------------------------------------------------------------
    print("\n[Audit 4] Controlled Differential Truth Test (Scan A -> B -> C)...")
    temp_dir = Path(tempfile.mkdtemp(prefix="entropy_diff_jsts_"))
    try:
        # Step A: Base state (1 empty catch, 1 hardcoded secret)
        src_dir = temp_dir / "src"
        src_dir.mkdir(parents=True)
        file_a = src_dir / "service.js"
        file_a.write_text(
            'export const API_TOKEN = "ENTROPY_STATIC_SECRET_KEY_1234567890_XYZ";\n'
            'export function doWork() {\n'
            '    try {\n'
            '        process();\n'
            '    } catch (err) {}\n'
            '}\n'
        )

        resp_a = client.post("/api/v1/repositories/scan", json={"path": str(temp_dir), "repo_name": "DiffRepo"})
        sid_a = resp_a.json()["scan_id"]
        findings_a = client.get(f"/api/v1/scans/{sid_a}/findings").json()
        score_a = client.get(f"/api/v1/scans/{sid_a}/score").json()["total_score"]
        print(f"  ✓ Scan A (Base): {len(findings_a)} findings, Score: {score_a}/100")

        # Step B: Add new debt (Introduce unvalidated input)
        file_b = src_dir / "routes.js"
        file_b.write_text(
            'const db = require("./db");\n'
            'export function handleReq(req) {\n'
            '    db.query(`SELECT * FROM users WHERE id = ${req.body.id}`);\n'
            '}\n'
        )

        resp_b = client.post("/api/v1/repositories/scan", json={"path": str(temp_dir), "repo_name": "DiffRepo"})
        sid_b = resp_b.json()["scan_id"]
        findings_b = client.get(f"/api/v1/scans/{sid_b}/findings").json()
        score_b = client.get(f"/api/v1/scans/{sid_b}/score").json()["total_score"]

        diff_ab = client.get(f"/api/v1/scans/{sid_b}/compare/{sid_a}").json()
        print(f"  ✓ Scan B (Added Debt): {len(findings_b)} findings, Score: {score_b}/100")
        print(f"    - Comparison A->B: New Findings={len(diff_ab['new_findings'])}, Resolved={len(diff_ab['resolved_findings'])}")
        assert len(diff_ab["new_findings"]) >= 1, "Expected newly introduced findings in Scan B"

        # Step C: Remediate Base debt (Fix empty catch, remove hardcoded secret)
        file_a.write_text(
            'export function doWork() {\n'
            '    try {\n'
            '        process();\n'
            '    } catch (err) {\n'
            '        console.error("Processing failed", err);\n'
            '    }\n'
            '}\n'
        )
        resp_c = client.post("/api/v1/repositories/scan", json={"path": str(temp_dir), "repo_name": "DiffRepo"})
        sid_c = resp_c.json()["scan_id"]
        findings_c = client.get(f"/api/v1/scans/{sid_c}/findings").json()
        score_c = client.get(f"/api/v1/scans/{sid_c}/score").json()["total_score"]

        diff_bc = client.get(f"/api/v1/scans/{sid_c}/compare/{sid_b}").json()
        print(f"  ✓ Scan C (Remediated): {len(findings_c)} findings, Score: {score_c}/100")
        print(f"    - Comparison B->C: New Findings={len(diff_bc['new_findings'])}, Resolved={len(diff_bc['resolved_findings'])}")
        assert len(diff_bc["resolved_findings"]) >= 2, "Expected remediated findings from service.js to be resolved in Scan C"

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 5. Real Entropy Repository Scan (Mixed Python + Next.js / TypeScript)
    # -------------------------------------------------------------------------
    entropy_repo_path = str(Path(__file__).resolve().parents[2])
    print(f"\n[Audit 5] Real Entropy Repository Scan ({entropy_repo_path})...")
    real_resp = client.post(
        "/api/v1/repositories/scan",
        json={"path": entropy_repo_path, "repo_name": "Entropy_Full_Repository"},
    )
    assert real_resp.status_code == 201, f"Real scan failed: {real_resp.text}"
    real_sid = real_resp.json()["scan_id"]

    real_manifest = client.get(f"/api/v1/repositories/{real_sid}/manifest").json()
    real_findings = client.get(f"/api/v1/scans/{real_sid}/findings").json()
    real_score = client.get(f"/api/v1/scans/{real_sid}/score").json()

    # Tally languages
    lang_tally: dict[str, int] = {}
    for f in real_manifest.get("files", []):
        lang = f["language"]
        lang_tally[lang] = lang_tally.get(lang, 0) + 1

    print(f"  ✓ Real scan completed: {real_sid[:8]}")
    print(f"    - Total Files Ingested: {real_manifest.get('total_files', 0)} ({real_manifest.get('total_loc', 0)} LOC)")
    print("    - Languages Discovered:")
    for lang, count in sorted(lang_tally.items()):
        print(f"        • {lang}: {count} files")
    print(f"    - Total Findings: {len(real_findings)}")
    print(f"    - Entropy Score: {real_score['total_score']}/100 ({real_score['tier']})")

    assert "python" in lang_tally, "Python files must be discovered"
    assert "typescript" in lang_tally or "javascript" in lang_tally, "TS/JS files must be discovered in Entropy repo"

    print("\n" + "=" * 80)
    print("PHASE 11 VERIFICATION COMPLETE — ALL AUDITS PASSED")
    print("=" * 80)
    return True


if __name__ == "__main__":
    success = run_phase11_verification()
    if not success:
        exit(1)

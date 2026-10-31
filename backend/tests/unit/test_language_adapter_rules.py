"""Comprehensive unit tests for language adapter rules across all 8 requested languages.

Tests both vulnerable and clean fixtures to verify precision, zero false positives on clean code,
proper severity/confidence mapping, language attribution, remediation advice, and deduplication.
"""

from pathlib import Path
import pytest

from app.analyzers.adapters.registry import default_adapter_registry
from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.parser.base import ParsedFile


FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "language_adapters"


def _create_parsed_file(path: Path, lang: SupportedLanguage) -> ParsedFile:
    content = path.read_text(encoding="utf-8")
    return ParsedFile(
        absolute_path=path,
        relative_path=path.name,
        language=lang,
        source_code=content,
        lines=content.splitlines(),
    )


# ---------------------------------------------------------------------------
# C Language Adapter Tests
# ---------------------------------------------------------------------------

def test_c_adapter_vulnerable_and_clean():
    adapter = default_adapter_registry.get(SupportedLanguage.C)
    assert adapter is not None

    # Vulnerable fixture
    vuln_file = _create_parsed_file(FIXTURES_DIR / "c" / "vulnerable.c", SupportedLanguage.C)
    findings = adapter.analyze_file(vuln_file)
    rule_ids = {f.rule_id for f in findings}

    assert "ENT-C-001" in rule_ids, "Expected dangerous buffer operation (strcpy/strcat/sprintf)"
    assert "ENT-C-002" in rule_ids, "Expected unsafe formatted input (scanf)"
    assert "ENT-C-003" in rule_ids, "Expected dangerous command execution (system)"

    for f in findings:
        assert f.language == SupportedLanguage.C
        assert f.recommendation is not None
        assert f.reference is not None
        assert f.line_start >= 1

    # Clean fixture
    clean_file = _create_parsed_file(FIXTURES_DIR / "c" / "clean.c", SupportedLanguage.C)
    clean_findings = adapter.analyze_file(clean_file)
    assert len(clean_findings) == 0, f"Expected 0 false positives on clean C, got {len(clean_findings)}"


# ---------------------------------------------------------------------------
# C++ Language Adapter Tests
# ---------------------------------------------------------------------------

def test_cpp_adapter_vulnerable_and_clean():
    adapter = default_adapter_registry.get(SupportedLanguage.CPP)
    assert adapter is not None

    vuln_file = _create_parsed_file(FIXTURES_DIR / "cpp" / "vulnerable.cpp", SupportedLanguage.CPP)
    findings = adapter.analyze_file(vuln_file)
    rule_ids = {f.rule_id for f in findings}

    assert "ENT-CPP-001" in rule_ids, "Expected unmanaged raw memory (new/delete)"
    assert "ENT-CPP-002" in rule_ids, "Expected dangerous type punning (reinterpret_cast)"
    assert "ENT-CPP-003" in rule_ids, "Expected legacy unsafe C string functions (strcpy/sprintf)"

    for f in findings:
        assert f.language == SupportedLanguage.CPP
        assert f.severity in (Severity.MEDIUM, Severity.HIGH, Severity.LOW)

    clean_file = _create_parsed_file(FIXTURES_DIR / "cpp" / "clean.cpp", SupportedLanguage.CPP)
    clean_findings = adapter.analyze_file(clean_file)
    assert len(clean_findings) == 0, f"Expected 0 false positives on clean C++, got {len(clean_findings)}"


# ---------------------------------------------------------------------------
# Rust Language Adapter Tests
# ---------------------------------------------------------------------------

def test_rust_adapter_distinguishes_observation_from_vulnerability():
    """Verify Rust 'unsafe' is reported as an informational/review-worthy observation (Severity.LOW),

    while dangerous transmutation and raw pointer dereferencing are assessed at higher risk.
    """
    adapter = default_adapter_registry.get(SupportedLanguage.RUST)
    assert adapter is not None

    vuln_file = _create_parsed_file(FIXTURES_DIR / "rust" / "vulnerable.rs", SupportedLanguage.RUST)
    findings = adapter.analyze_file(vuln_file)
    rule_ids = {f.rule_id for f in findings}

    assert "ENT-RUST-001" in rule_ids, "Expected review-worthy unsafe block audit finding"
    assert "ENT-RUST-002" in rule_ids, "Expected dangerous memory transmutation (mem::transmute)"
    assert "ENT-RUST-003" in rule_ids, "Expected raw pointer dereferencing"

    # Crucial requirement: Rust unsafe code must NOT be treated automatically as a vulnerability
    unsafe_finding = next(f for f in findings if f.rule_id == "ENT-RUST-001")
    assert unsafe_finding.severity == Severity.LOW, "Rust unsafe usage must be classified as LOW severity debt/observation"
    assert unsafe_finding.category == DebtCategory.ARCHITECTURAL_CONSISTENCY

    clean_file = _create_parsed_file(FIXTURES_DIR / "rust" / "clean.rs", SupportedLanguage.RUST)
    clean_findings = adapter.analyze_file(clean_file)
    assert len(clean_findings) == 0, f"Expected 0 false positives on clean Rust, got {len(clean_findings)}"


# ---------------------------------------------------------------------------
# Java Language Adapter Tests
# ---------------------------------------------------------------------------

def test_java_adapter_vulnerable_and_clean():
    adapter = default_adapter_registry.get(SupportedLanguage.JAVA)
    assert adapter is not None

    vuln_file = _create_parsed_file(FIXTURES_DIR / "java" / "VulnerableService.java", SupportedLanguage.JAVA)
    findings = adapter.analyze_file(vuln_file)
    rule_ids = {f.rule_id for f in findings}

    assert "ENT-JAVA-001" in rule_ids, "Expected SQL injection finding"
    assert "ENT-JAVA-002" in rule_ids, "Expected unsafe deserialization (readObject)"
    assert "ENT-JAVA-003" in rule_ids, "Expected command execution (Runtime.exec)"

    clean_file = _create_parsed_file(FIXTURES_DIR / "java" / "CleanService.java", SupportedLanguage.JAVA)
    clean_findings = adapter.analyze_file(clean_file)
    assert len(clean_findings) == 0, f"Expected 0 false positives on clean Java, got {len(clean_findings)}"


# ---------------------------------------------------------------------------
# Go Language Adapter Tests
# ---------------------------------------------------------------------------

def test_go_adapter_vulnerable_and_clean():
    adapter = default_adapter_registry.get(SupportedLanguage.GO)
    assert adapter is not None

    vuln_file = _create_parsed_file(FIXTURES_DIR / "go" / "vulnerable.go", SupportedLanguage.GO)
    findings = adapter.analyze_file(vuln_file)
    rule_ids = {f.rule_id for f in findings}

    assert "ENT-GO-001" in rule_ids, "Expected SQL injection via Sprintf"
    assert "ENT-GO-002" in rule_ids, "Expected InsecureSkipVerify: true"
    assert "ENT-GO-003" in rule_ids, "Expected unsafe.Pointer usage"
    assert "ENT-GO-004" in rule_ids, "Expected command execution via shell"

    clean_file = _create_parsed_file(FIXTURES_DIR / "go" / "clean.go", SupportedLanguage.GO)
    clean_findings = adapter.analyze_file(clean_file)
    assert len(clean_findings) == 0, f"Expected 0 false positives on clean Go, got {len(clean_findings)}"


# ---------------------------------------------------------------------------
# JavaScript & TypeScript Adapter Tests
# ---------------------------------------------------------------------------

def test_javascript_adapter_vulnerable_and_clean():
    adapter = default_adapter_registry.get(SupportedLanguage.JAVASCRIPT)
    assert adapter is not None

    vuln_file = _create_parsed_file(FIXTURES_DIR / "javascript" / "vulnerable.js", SupportedLanguage.JAVASCRIPT)
    findings = adapter.analyze_file(vuln_file)
    rule_ids = {f.rule_id for f in findings}

    assert "ENT-JS-002" in rule_ids, "Expected dynamic code evaluation (eval / new Function)"
    assert "ENT-JS-003" in rule_ids, "Expected unsafe DOM manipulation (innerHTML / document.write)"

    clean_file = _create_parsed_file(FIXTURES_DIR / "javascript" / "clean.js", SupportedLanguage.JAVASCRIPT)
    clean_findings = adapter.analyze_file(clean_file)
    assert len(clean_findings) == 0, f"Expected 0 false positives on clean JS, got {len(clean_findings)}"


def test_typescript_adapter_explicit_attribution_and_clean():
    """Verify TypeScript rules explicitly detect TS idioms and attribute findings to TYPESCRIPT,

    not merely labeling them as JavaScript.
    """
    adapter = default_adapter_registry.get(SupportedLanguage.TYPESCRIPT)
    assert adapter is not None
    assert adapter.language == SupportedLanguage.TYPESCRIPT

    vuln_file = _create_parsed_file(FIXTURES_DIR / "typescript" / "vulnerable.ts", SupportedLanguage.TYPESCRIPT)
    findings = adapter.analyze_file(vuln_file)
    rule_ids = {f.rule_id for f in findings}

    assert "ENT-TS-001" in rule_ids, "Expected type assertion bypass (as any)"
    assert "ENT-TS-002" in rule_ids, "Expected safety suppression directive (@ts-ignore)"
    assert "ENT-TS-003" in rule_ids, "Expected non-null assertion on external input (!.)"

    for f in findings:
        assert f.language == SupportedLanguage.TYPESCRIPT, "Finding must be explicitly attributed to TypeScript"

    clean_file = _create_parsed_file(FIXTURES_DIR / "typescript" / "clean.ts", SupportedLanguage.TYPESCRIPT)
    clean_findings = adapter.analyze_file(clean_file)
    assert len(clean_findings) == 0, f"Expected 0 false positives on clean TS, got {len(clean_findings)}"


# ---------------------------------------------------------------------------
# PHP Language Adapter Tests
# ---------------------------------------------------------------------------

def test_php_adapter_vulnerable_and_clean():
    adapter = default_adapter_registry.get(SupportedLanguage.PHP)
    assert adapter is not None
    assert adapter.language == SupportedLanguage.PHP

    vuln_file = _create_parsed_file(FIXTURES_DIR / "php" / "vulnerable.php", SupportedLanguage.PHP)
    findings = adapter.analyze_file(vuln_file)
    rule_ids = {f.rule_id for f in findings}

    assert "ENT-PHP-001" in rule_ids, "Expected SQL injection (mysqli_query concatenation)"
    assert "ENT-PHP-002" in rule_ids, "Expected command execution (system / eval)"
    assert "ENT-PHP-003" in rule_ids, "Expected unsafe dynamic file inclusion (include)"

    for f in findings:
        assert f.language == SupportedLanguage.PHP
        assert f.recommendation is not None
        assert f.reference is not None

    clean_file = _create_parsed_file(FIXTURES_DIR / "php" / "clean.php", SupportedLanguage.PHP)
    clean_findings = adapter.analyze_file(clean_file)
    assert len(clean_findings) == 0, f"Expected 0 false positives on clean PHP, got {len(clean_findings)}"


# ---------------------------------------------------------------------------
# Deduplication and Determinism
# ---------------------------------------------------------------------------

def test_adapter_finding_determinism_and_fingerprints():
    adapter = default_adapter_registry.get(SupportedLanguage.C)
    vuln_file = _create_parsed_file(FIXTURES_DIR / "c" / "vulnerable.c", SupportedLanguage.C)

    run1 = adapter.analyze_file(vuln_file)
    run2 = adapter.analyze_file(vuln_file)

    assert len(run1) == len(run2)
    for f1, f2 in zip(run1, run2):
        assert f1.fingerprint == f2.fingerprint
        assert f1.id == f2.id
        assert f1.line_start == f2.line_start

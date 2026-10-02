"""Unit and integration tests for Phase 11 JavaScript and TypeScript static analysis engine."""

from __future__ import annotations

import os
from pathlib import Path

from app.analyzers.architecture.analyzer import ArchitecturalConsistencyAnalyzer
from app.analyzers.base import AnalysisContext
from app.analyzers.duplication.analyzer import CodeDuplicationDebtAnalyzer
from app.analyzers.jsts_context import JSTSASTContext
from app.analyzers.jsts_rules.error_handling import (
    JSEmptyCatchRule,
    JSSwallowedErrorFallbackRule,
)
from app.analyzers.jsts_rules.input_validation import JSUnvalidatedInputRule
from app.analyzers.jsts_rules.logging_secrets import (
    JSHardcodedSecretRule,
    JSInsecureSecretFallbackRule,
    JSSensitiveLogRule,
)
from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.parser.jsts.parser import JSTSParser
from app.parser.python.models import ParseStatus
from app.repository.discoverer import RepositoryDiscoverer
from app.services.analysis_service import AnalysisService
from app.services.repository_service import RepositoryService

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
JS_FIXTURES = FIXTURES_DIR / "javascript"
TS_FIXTURES = FIXTURES_DIR / "typescript"


class TestJSTSParser:
    """Test safe Tree-sitter parsing for JS, TS, JSX, TSX without code execution."""

    def test_parse_clean_javascript(self) -> None:
        parser = JSTSParser()
        clean_file = JS_FIXTURES / "clean.js"
        unit = parser.parse_file(clean_file, "javascript/clean.js", SupportedLanguage.JAVASCRIPT)

        assert unit.is_valid
        assert unit.status == ParseStatus.SUCCESS
        assert unit.language == SupportedLanguage.JAVASCRIPT
        assert unit.line_count > 0
        assert unit.structure is not None
        assert len(unit.structure.functions) == 2
        assert len(unit.structure.exports) == 2

    def test_parse_clean_typescript(self) -> None:
        parser = JSTSParser()
        clean_file = TS_FIXTURES / "clean.ts"
        unit = parser.parse_file(clean_file, "typescript/clean.ts", SupportedLanguage.TYPESCRIPT)

        assert unit.is_valid
        assert unit.status == ParseStatus.SUCCESS
        assert unit.language == SupportedLanguage.TYPESCRIPT
        assert unit.structure is not None
        assert len(unit.structure.classes) == 1
        cls = unit.structure.classes[0]
        assert cls.name == "MetricsCollector"
        assert len(cls.methods) >= 2

    def test_parse_jsx_and_tsx_components(self) -> None:
        parser = JSTSParser()
        jsx_file = JS_FIXTURES / "component.jsx"
        unit_jsx = parser.parse_file(jsx_file, "javascript/component.jsx", SupportedLanguage.JAVASCRIPT)
        assert unit_jsx.is_valid
        assert unit_jsx.structure is not None
        assert "react" in unit_jsx.structure.frameworks

        tsx_file = TS_FIXTURES / "component.tsx"
        unit_tsx = parser.parse_file(tsx_file, "typescript/component.tsx", SupportedLanguage.TYPESCRIPT)
        assert unit_tsx.is_valid
        assert unit_tsx.structure is not None
        assert "react" in unit_tsx.structure.frameworks

    def test_broken_syntax_handling_never_crashes(self) -> None:
        parser = JSTSParser()
        broken_js = JS_FIXTURES / "broken_syntax.js"
        unit = parser.parse_file(broken_js, "javascript/broken_syntax.js", SupportedLanguage.JAVASCRIPT)

        assert unit.status == ParseStatus.SYNTAX_ERROR
        assert len(unit.errors) > 0
        assert unit.error_location is not None

        broken_ts = TS_FIXTURES / "broken_syntax.ts"
        unit_ts = parser.parse_file(broken_ts, "typescript/broken_syntax.ts", SupportedLanguage.TYPESCRIPT)
        assert unit_ts.status == ParseStatus.SYNTAX_ERROR
        assert len(unit_ts.errors) > 0

    def test_missing_file_handling(self) -> None:
        parser = JSTSParser()
        non_existent = JS_FIXTURES / "does_not_exist.js"
        unit = parser.parse_file(non_existent, "does_not_exist.js", SupportedLanguage.JAVASCRIPT)
        assert unit.status == ParseStatus.READ_ERROR
        assert not unit.is_valid


class TestJSTSErrorHandlingRules:
    """Test ENT-ERR-JS-001 and ENT-ERR-JS-002."""

    def test_empty_catch_detection(self) -> None:
        parser = JSTSParser()
        unit = parser.parse_file(
            JS_FIXTURES / "error_handling.js",
            "javascript/error_handling.js",
            SupportedLanguage.JAVASCRIPT,
        )
        ctx = JSTSASTContext(unit)
        rule = JSEmptyCatchRule()
        findings = rule.analyze(ctx)

        # Expect 2 empty catch blocks in error_handling.js (parsePayload, readConfig)
        assert len(findings) == 2
        for f in findings:
            assert f.rule_id == "ENT-ERR-JS-001"
            assert f.category == DebtCategory.ERROR_HANDLING
            assert f.file == "javascript/error_handling.js"

    def test_swallowed_error_fallback_detection(self) -> None:
        parser = JSTSParser()
        unit = parser.parse_file(
            JS_FIXTURES / "error_handling.js",
            "javascript/error_handling.js",
            SupportedLanguage.JAVASCRIPT,
        )
        ctx = JSTSASTContext(unit)
        rule = JSSwallowedErrorFallbackRule()
        findings = rule.analyze(ctx)

        # Expect 2 swallowed fallbacks (fetchUserData returns null, verifySignature returns false)
        assert len(findings) == 2
        for f in findings:
            assert f.rule_id == "ENT-ERR-JS-002"
            assert f.category == DebtCategory.ERROR_HANDLING

    def test_intentional_comment_suppresses_empty_catch(self) -> None:
        parser = JSTSParser()
        unit = parser.parse_file(
            JS_FIXTURES / "false_positives.js",
            "javascript/false_positives.js",
            SupportedLanguage.JAVASCRIPT,
        )
        ctx = JSTSASTContext(unit)
        rule = JSEmptyCatchRule()
        findings = rule.analyze(ctx)
        # Empty catch in testIgnoredError has "// intentional cleanup ignore" -> should not be flagged
        assert len(findings) == 0

    def test_logging_before_fallback_suppresses_swallowed_error(self) -> None:
        parser = JSTSParser()
        unit = parser.parse_file(
            JS_FIXTURES / "false_positives.js",
            "javascript/false_positives.js",
            SupportedLanguage.JAVASCRIPT,
        )
        ctx = JSTSASTContext(unit)
        rule = JSSwallowedErrorFallbackRule()
        findings = rule.analyze(ctx)
        # safeGetConfig logs with console.error before returning null -> should not be flagged
        assert len(findings) == 0


class TestJSTSInputValidationRule:
    """Test ENT-INPUT-JS-001."""

    def test_unvalidated_input_in_sink_detected(self) -> None:
        parser = JSTSParser()
        unit = parser.parse_file(
            JS_FIXTURES / "input_validation.js",
            "javascript/input_validation.js",
            SupportedLanguage.JAVASCRIPT,
        )
        ctx = JSTSASTContext(unit)
        rule = JSUnvalidatedInputRule()
        findings = rule.analyze(ctx)

        assert len(findings) == 2
        for f in findings:
            assert f.rule_id == "ENT-INPUT-JS-001"
            assert f.category == DebtCategory.INPUT_VALIDATION

    def test_schema_validated_input_not_flagged(self) -> None:
        parser = JSTSParser()
        unit = parser.parse_file(
            JS_FIXTURES / "false_positives.js",
            "javascript/false_positives.js",
            SupportedLanguage.JAVASCRIPT,
        )
        ctx = JSTSASTContext(unit)
        rule = JSUnvalidatedInputRule()
        findings = rule.analyze(ctx)

        # Uses Zod schema parse before query -> should not be flagged
        assert len(findings) == 0


class TestJSTSLoggingAndSecretsRules:
    """Test ENT-LOG-JS-001, ENT-LOG-JS-002, and ENT-LOG-JS-003."""

    def test_sensitive_log_detection_and_redaction(self) -> None:
        parser = JSTSParser()
        unit = parser.parse_file(
            JS_FIXTURES / "logging.js",
            "javascript/logging.js",
            SupportedLanguage.JAVASCRIPT,
        )
        ctx = JSTSASTContext(unit)
        rule = JSSensitiveLogRule()
        findings = rule.analyze(ctx)

        assert len(findings) == 2
        for f in findings:
            assert f.rule_id == "ENT-LOG-JS-001"
            assert f.category == DebtCategory.LOGGING_AND_SECRETS

    def test_hardcoded_secrets_detection(self) -> None:
        parser = JSTSParser()
        unit = parser.parse_file(
            JS_FIXTURES / "secrets.js",
            "javascript/secrets.js",
            SupportedLanguage.JAVASCRIPT,
        )
        ctx = JSTSASTContext(unit)
        rule = JSHardcodedSecretRule()
        findings = rule.analyze(ctx)

        # Expect API_KEY and JWT_SECRET flagged
        assert len(findings) >= 2
        rule_ids = [f.rule_id for f in findings]
        assert all(rid == "ENT-LOG-JS-002" for rid in rule_ids)

    def test_insecure_secret_fallback_detection(self) -> None:
        parser = JSTSParser()
        unit = parser.parse_file(
            JS_FIXTURES / "secrets.js",
            "javascript/secrets.js",
            SupportedLanguage.JAVASCRIPT,
        )
        ctx = JSTSASTContext(unit)
        rule = JSInsecureSecretFallbackRule()
        findings = rule.analyze(ctx)

        # DATABASE_PASSWORD || fallback
        assert len(findings) == 1
        assert findings[0].rule_id == "ENT-LOG-JS-003"
        assert findings[0].symbol == "DATABASE_PASSWORD"

    def test_benign_env_and_logs_not_flagged(self) -> None:
        parser = JSTSParser()
        unit = parser.parse_file(
            JS_FIXTURES / "false_positives.js",
            "javascript/false_positives.js",
            SupportedLanguage.JAVASCRIPT,
        )
        ctx = JSTSASTContext(unit)

        log_findings = JSSensitiveLogRule().analyze(ctx)
        secret_findings = JSHardcodedSecretRule().analyze(ctx)
        fallback_findings = JSInsecureSecretFallbackRule().analyze(ctx)

        assert len(log_findings) == 0
        assert len(secret_findings) == 0
        assert len(fallback_findings) == 0


class TestJSTSDuplication:
    """Test AST normalizer and duplication detector on JS/TS functions."""

    def test_javascript_duplication_detected(self) -> None:
        parser = JSTSParser()
        unit = parser.parse_file(
            JS_FIXTURES / "duplication.js",
            "javascript/duplication.js",
            SupportedLanguage.JAVASCRIPT,
        )
        manifest = RepositoryDiscoverer().discover_repository(JS_FIXTURES)
        ctx = AnalysisContext.from_python_units(
            repo_path=JS_FIXTURES,
            units=[],
            manifest=manifest,
            jsts_units=[unit],
        )
        analyzer = CodeDuplicationDebtAnalyzer()
        findings = analyzer.analyze(ctx)

        # Expect duplication finding between processOrderBatch and processInvoiceBatch
        assert len(findings) >= 1
        assert any(f.rule_id in ("ENT-DUP-001", "ENT-DUP-002") for f in findings)

    def test_typescript_duplication_detected(self) -> None:
        parser = JSTSParser()
        unit = parser.parse_file(
            TS_FIXTURES / "duplication.ts",
            "typescript/duplication.ts",
            SupportedLanguage.TYPESCRIPT,
        )
        manifest = RepositoryDiscoverer().discover_repository(TS_FIXTURES)
        ctx = AnalysisContext.from_python_units(
            repo_path=TS_FIXTURES,
            units=[],
            manifest=manifest,
            jsts_units=[unit],
        )
        analyzer = CodeDuplicationDebtAnalyzer()
        findings = analyzer.analyze(ctx)

        assert len(findings) >= 1
        assert any(f.rule_id in ("ENT-DUP-001", "ENT-DUP-002") for f in findings)


class TestJSTSArchitecture:
    """Test module graph extraction and circular dependency detection in JS/TS."""

    def test_circular_dependency_detected(self) -> None:
        parser = JSTSParser()
        unit_a = parser.parse_file(
            JS_FIXTURES / "architecture_a.js",
            "javascript/architecture_a.js",
            SupportedLanguage.JAVASCRIPT,
        )
        unit_b = parser.parse_file(
            JS_FIXTURES / "architecture_b.js",
            "javascript/architecture_b.js",
            SupportedLanguage.JAVASCRIPT,
        )

        manifest = RepositoryDiscoverer().discover_repository(JS_FIXTURES)
        ctx = AnalysisContext.from_python_units(
            repo_path=JS_FIXTURES,
            units=[],
            manifest=manifest,
            jsts_units=[unit_a, unit_b],
        )
        analyzer = ArchitecturalConsistencyAnalyzer()
        findings = analyzer.analyze(ctx)

        circ_findings = [f for f in findings if f.rule_id == "ENT-ARCH-001"]
        assert len(circ_findings) >= 1


class TestZeroCodeExecutionCanary:
    """Validate strict invariant: target JS/TS files are NEVER executed."""

    def test_malicious_canaries_never_execute(self) -> None:
        canary_js_file = "/tmp/malicious_js_executed.txt"
        canary_ts_file = "/tmp/malicious_ts_executed.txt"

        for p in (canary_js_file, canary_ts_file):
            if os.path.exists(p):
                os.remove(p)

        parser = JSTSParser()
        # Parse JS canary
        unit_js = parser.parse_file(
            JS_FIXTURES / "malicious.js",
            "javascript/malicious.js",
            SupportedLanguage.JAVASCRIPT,
        )
        # Parse TS canary
        unit_ts = parser.parse_file(
            TS_FIXTURES / "malicious.ts",
            "typescript/malicious.ts",
            SupportedLanguage.TYPESCRIPT,
        )

        assert unit_js.is_valid
        assert unit_ts.is_valid

        # Canaries must NOT have run
        assert not os.path.exists(canary_js_file), "CRITICAL: Malicious JS code executed!"
        assert not os.path.exists(canary_ts_file), "CRITICAL: Malicious TS code executed!"


class TestDeterminismAndRepeatability:
    """Scan the JS fixture repository twice and assert exact byte-for-byte and finding match."""

    def test_repeat_scan_determinism(self) -> None:
        repo_svc = RepositoryService()
        analysis_svc = AnalysisService(repo_service=repo_svc)

        scan_1 = repo_svc.execute_scan(str(JS_FIXTURES), "javascript_fixtures")
        findings_1 = analysis_svc.analyze_scan(scan_1.scan_id, force_reanalyze=True)

        scan_2 = repo_svc.execute_scan(str(JS_FIXTURES), "javascript_fixtures")
        findings_2 = analysis_svc.analyze_scan(scan_2.scan_id, force_reanalyze=True)

        assert len(findings_1) == len(findings_2)
        assert [f.id for f in findings_1] == [f.id for f in findings_2]
        assert [f.fingerprint for f in findings_1] == [f.fingerprint for f in findings_2]
        assert [f.rule_id for f in findings_1] == [f.rule_id for f in findings_2]

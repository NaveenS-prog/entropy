"""Deterministic static analysis rules for Rust language codebases."""

from __future__ import annotations

import re

from app.models.domain.enums import Confidence, DebtCategory, Severity, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.parser.base import ParsedFile

# Regex for detecting `unsafe` usage: unsafe block, unsafe fn, unsafe impl, unsafe trait
RUST_UNSAFE_REGEX = re.compile(r"\bunsafe\s*(?:\{|\bfn\b|\bimpl\b|\btrait\b)", re.ASCII)

# High-risk transmutation: std::mem::transmute or mem::transmute
RUST_TRANSMUTE_REGEX = re.compile(r"\b(?:std::)?mem::transmute\b", re.ASCII)

# Raw pointer dereferencing: *ptr, *raw_ptr, (*ptr) inside unsafe code
RUST_RAW_PTR_DEREF_REGEX = re.compile(
    r"(?<![a-zA-Z0-9_])\*([a-zA-Z_][a-zA-Z0-9_]*(?:ptr|raw|mut|buf)[a-zA-Z0-9_]*|\([a-zA-Z0-9_]+\))\b",
    re.ASCII,
)


RULE_RUST_001 = RuleDefinition(
    rule_id="ENT-RUST-001",
    category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
    title="Review-Worthy 'unsafe' Block / Function in Rust",
    description="Identifies observable 'unsafe' blocks, functions, or implementations in Rust code. This is an informational observation and review-worthy construct, not a confirmed vulnerability.",
    default_severity=Severity.LOW,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.RUST],
    impact_template="Unsafe blocks bypass Rust's compiler borrow checker guarantees; unreviewed unsafe code can introduce subtle memory corruption or race conditions.",
    recommendation_template="Document the safety invariants with a '// SAFETY:' comment explaining why the operation is sound, and encapsulate unsafe logic in safe abstractions.",
    rationale="Rust 'unsafe' is a necessary systems programming mechanism, but accumulating undocumented unsafe blocks represents architectural review debt.",
)

RULE_RUST_002 = RuleDefinition(
    rule_id="ENT-RUST-002",
    category=DebtCategory.ARCHITECTURAL_CONSISTENCY,
    title="High-Risk Memory Transmutation via mem::transmute",
    description="Detects std::mem::transmute operations in Rust, which arbitrarily reinterpret the bits of a value as another type without safety checks.",
    default_severity=Severity.MEDIUM,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.RUST],
    impact_template="mem::transmute causes instant undefined behavior if source and destination types have different sizes, alignment, or invalid bit patterns.",
    recommendation_template="Use safe conversion traits (From, TryFrom), bytemuck for byte casting, or pointer casting with explicit layout guarantees.",
    rationale="Transmutation is among the most error-prone primitives in Rust systems programming.",
)

RULE_RUST_003 = RuleDefinition(
    rule_id="ENT-RUST-003",
    category=DebtCategory.INPUT_VALIDATION,
    title="Raw Pointer Dereference in Rust",
    description="Detects raw pointer dereferencing (*ptr) in Rust code, which can trigger null pointer dereferences, unaligned reads, or use-after-free.",
    default_severity=Severity.MEDIUM,
    default_confidence=Confidence.HIGH,
    languages=[SupportedLanguage.RUST],
    impact_template="Dereferencing raw pointers without bounds or nullness verification compromises Rust's memory safety guarantees.",
    recommendation_template="Verify pointer non-nullness (e.g. NonNull<T>) and alignment before dereferencing, or use safe references where possible.",
    rationale="Raw pointer manipulation represents a critical boundary where defensive validation is mandatory.",
)


def _strip_rust_comments(line: str, in_block: bool) -> tuple[str, bool]:
    if in_block:
        if "*/" in line:
            _, after = line.split("*/", 1)
            rest, still_in = _strip_rust_comments(after, False)
            return (" " * (len(line) - len(rest))) + rest, still_in
        return " " * len(line), True

    if "/*" in line:
        before, after = line.split("/*", 1)
        if "*/" in after:
            _, end_after = after.split("*/", 1)
            processed_end, _ = _strip_rust_comments(end_after, False)
            return before + " " * (len(line) - len(before) - len(processed_end)) + processed_end, False
        return before + " " * (len(line) - len(before)), True

    if "//" in line:
        before, _ = line.split("//", 1)
        return before, False

    return line, False


def check_rust_rules(file: ParsedFile) -> list[Finding]:
    """Analyze a Rust source file and return deterministic findings."""
    findings: list[Finding] = []
    in_block = False

    for idx, raw_line in enumerate(file.lines, start=1):
        clean_line, in_block = _strip_rust_comments(raw_line, in_block)
        stripped = clean_line.strip()
        if not stripped:
            continue

        # 1. Check review-worthy unsafe usage
        match_unsafe = RUST_UNSAFE_REGEX.search(clean_line)
        if match_unsafe:
            evidence = file.extract_snippet(idx, idx)
            finding_id = Finding.generate_deterministic_id(
                rule_id=RULE_RUST_001.rule_id,
                file=file.relative_path,
                line_start=idx,
                line_end=idx,
                symbol="unsafe",
                evidence_signature=stripped,
            )
            fingerprint = Finding.generate_fingerprint(
                rule_id=RULE_RUST_001.rule_id,
                file=file.relative_path,
                symbol="unsafe",
                pattern_signature=f"rust_unsafe:{stripped}",
            )
            findings.append(
                Finding(
                    id=finding_id,
                    category=RULE_RUST_001.category,
                    rule_id=RULE_RUST_001.rule_id,
                    severity=RULE_RUST_001.default_severity,  # LOW (informational observation, not a confirmed vulnerability)
                    confidence=RULE_RUST_001.default_confidence,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    column_start=match_unsafe.start(),
                    column_end=match_unsafe.end(),
                    symbol="unsafe",
                    title="Review-Worthy 'unsafe' Block in Rust",
                    description="Observable 'unsafe' construct detected. Requires safety invariant documentation (// SAFETY:) and careful peer review.",
                    evidence=evidence,
                    impact=RULE_RUST_001.impact_template,
                    recommendation=RULE_RUST_001.recommendation_template,
                    fingerprint=fingerprint,
                    language=SupportedLanguage.RUST,
                    reference="https://doc.rust-lang.org/nomicon/meet-safe-and-unsafe.html",
                    metadata={"construct": "unsafe", "language": "rust", "finding_nature": "informational_observation"},
                )
            )

        # 2. Check mem::transmute
        match_transmute = RUST_TRANSMUTE_REGEX.search(clean_line)
        if match_transmute:
            evidence = file.extract_snippet(idx, idx)
            finding_id = Finding.generate_deterministic_id(
                rule_id=RULE_RUST_002.rule_id,
                file=file.relative_path,
                line_start=idx,
                line_end=idx,
                symbol="mem::transmute",
                evidence_signature=stripped,
            )
            fingerprint = Finding.generate_fingerprint(
                rule_id=RULE_RUST_002.rule_id,
                file=file.relative_path,
                symbol="mem::transmute",
                pattern_signature=f"rust_transmute:{stripped}",
            )
            findings.append(
                Finding(
                    id=finding_id,
                    category=RULE_RUST_002.category,
                    rule_id=RULE_RUST_002.rule_id,
                    severity=RULE_RUST_002.default_severity,
                    confidence=RULE_RUST_002.default_confidence,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    column_start=match_transmute.start(),
                    column_end=match_transmute.end(),
                    symbol="mem::transmute",
                    title="High-Risk mem::transmute in Rust",
                    description="Arbitrary bitwise type transmutation detected via 'mem::transmute'.",
                    evidence=evidence,
                    impact=RULE_RUST_002.impact_template,
                    recommendation=RULE_RUST_002.recommendation_template,
                    fingerprint=fingerprint,
                    language=SupportedLanguage.RUST,
                    reference="https://doc.rust-lang.org/std/mem/fn.transmute.html",
                    metadata={"function": "mem::transmute", "language": "rust"},
                )
            )

        # 3. Check raw pointer dereferencing
        if "*" in clean_line and ("ptr" in clean_line or "raw" in clean_line):
            match_ptr = RUST_RAW_PTR_DEREF_REGEX.search(clean_line)
            if match_ptr:
                evidence = file.extract_snippet(idx, idx)
                finding_id = Finding.generate_deterministic_id(
                    rule_id=RULE_RUST_003.rule_id,
                    file=file.relative_path,
                    line_start=idx,
                    line_end=idx,
                    symbol="raw_ptr_deref",
                    evidence_signature=stripped,
                )
                fingerprint = Finding.generate_fingerprint(
                    rule_id=RULE_RUST_003.rule_id,
                    file=file.relative_path,
                    symbol="raw_ptr_deref",
                    pattern_signature=f"raw_ptr:{stripped}",
                )
                findings.append(
                    Finding(
                        id=finding_id,
                        category=RULE_RUST_003.category,
                        rule_id=RULE_RUST_003.rule_id,
                        severity=RULE_RUST_003.default_severity,
                        confidence=RULE_RUST_003.default_confidence,
                        file=file.relative_path,
                        line_start=idx,
                        line_end=idx,
                        column_start=match_ptr.start(),
                        column_end=match_ptr.end(),
                        symbol="raw_ptr_deref",
                        title="Raw Pointer Dereference in Rust",
                        description="Dereference of a raw pointer (*ptr) observed.",
                        evidence=evidence,
                        impact=RULE_RUST_003.impact_template,
                        recommendation=RULE_RUST_003.recommendation_template,
                        fingerprint=fingerprint,
                        language=SupportedLanguage.RUST,
                        reference="https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html#dereferencing-a-raw-pointer",
                        metadata={"construct": "raw_pointer_dereference", "language": "rust"},
                    )
                )

    return findings

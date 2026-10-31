# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Software engineers, security-minded technical leads, and platform teams reviewing a repository's structural health. They use Entropy during local development, repository reviews, and pull-request workflows to understand where architectural and security debt needs attention.

## Product Purpose

Entropy is an architectural security-debt analyzer for codebases built with or without AI assistance. It scans source trees deterministically, without executing repository code, then presents the resulting structural findings, score, and policy status for investigation and remediation.

## Positioning

Unlike a CVE scanner or tool that speculates about code authorship, Entropy measures verifiable AST-level patterns: structural drift, inconsistent authorization, missing validation boundaries, logging and secret risks, duplicate code, and architectural violations.

## Operating Context

The primary workflow is selecting a repository scan, triaging findings by severity and category, reviewing architecture or route posture, comparing pull-request deltas, and exporting reports for CI and review. The dashboard must prioritize scanability, risk signals, exact provenance, and clear empty or error states.

## Capabilities and Constraints

- Scores and findings originate from the backend's deterministic analysis; the interface must not invent scan results or hard-code metrics.
- The score is a heuristic for architectural and security debt, not exploit probability or evidence of AI authorship.
- The existing Next.js 14, Tailwind CSS, and lucide-react stack remains in place.
- Existing routes, API interactions, downloads, scan selection, and workspace controls must keep working.

## Brand Commitments

The product name is Entropy. Its voice is precise, sober, and evidence-led: it reports observable structure rather than making claims beyond the analysis.

## Evidence on Hand

Repository documentation, the engineering constitution, deterministic score data, scan findings, AST manifests, policy evaluation, and SARIF/JSON report exports. No external customer proof, benchmark, or marketing claims should be fabricated.

## Product Principles

1. Make urgent risk and provenance legible before secondary detail.
2. Treat every finding as evidence to inspect, not an opaque verdict.
3. Keep the scanner's limits visible and do not imply runtime exploit verification.
4. Preserve a deliberate, calm operating environment under high information density.

## Accessibility & Inclusion

Use semantic controls, visible keyboard focus, sufficient text contrast, and layouts that remain usable at small viewport widths and with reduced motion enabled.

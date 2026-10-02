"""Context builder extracting minimal, redacted finding data for AI explanation.

Adheres strictly to the principle of least privilege:
- Repository code is untrusted data.
- Only metadata, evidence, and small redacted snippet are extracted.
- Secrets are aggressively redacted before context generation.
"""

from __future__ import annotations

import logging
from pathlib import Path

from app.ai.redaction import redact_secrets
from app.models.domain.ai_explanation import AIExplanationContext
from app.models.domain.finding import Finding

logger = logging.getLogger("entropy.ai.context")


def build_explanation_context(
    finding: Finding,
    root_path: Path | None = None,
    snippet_padding: int = 5,
) -> AIExplanationContext:
    """Build a sanitized, redacted AIExplanationContext from a deterministic finding."""
    evidence_content = finding.evidence.content if finding.evidence else ""
    redacted_evidence = redact_secrets(evidence_content)

    source_snippet = None
    if root_path:
        try:
            target_file = root_path / finding.file
            if target_file.is_file() and target_file.exists():
                lines = target_file.read_text(encoding="utf-8", errors="replace").splitlines()
                start_line = max(1, finding.line_start - snippet_padding)
                end_line = min(len(lines), finding.line_end + snippet_padding)

                # Format snippet with line numbers
                snippet_lines = [
                    f"{line_num}: {lines[line_num - 1]}"
                    for line_num in range(start_line, end_line + 1)
                ]
                raw_snippet = "\n".join(snippet_lines)
                source_snippet = redact_secrets(raw_snippet)
        except Exception as err:
            logger.debug("Could not read source snippet for %s: %s", finding.file, err)

    if not source_snippet:
        source_snippet = redacted_evidence

    return AIExplanationContext(
        rule_id=finding.rule_id,
        category=finding.category.value if hasattr(finding.category, "value") else str(finding.category),
        severity=finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
        confidence=finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence),
        message=redact_secrets(finding.description or finding.title),
        file_path=finding.file,
        line_start=finding.line_start,
        line_end=finding.line_end,
        evidence=redacted_evidence,
        source_snippet=source_snippet,
        fingerprint=finding.fingerprint,
    )

"""SARIF 2.1.0 formatter for Entropy findings."""

from __future__ import annotations

from typing import Any

from app.core.config import settings
from app.models.domain.enums import Severity
from app.models.domain.finding import Finding
from app.models.domain.scan import RepositoryScanResult

# Map Entropy Severity to SARIF 2.1.0 levels
# Allowed SARIF levels: "error", "warning", "note", "none"
SEVERITY_TO_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def finding_to_sarif_result(finding: Finding) -> dict[str, Any]:
    """Convert a single Entropy Finding to a SARIF 2.1.0 result object."""
    level = SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning")

    # Artifact location with forward slashes for URI compatibility
    uri_path = finding.file.replace("\\", "/")

    region: dict[str, Any] = {
        "startLine": finding.line_start,
        "endLine": finding.line_end,
    }
    if finding.column_start is not None:
        # SARIF columns are 1-indexed, while column_start in Finding is 0-indexed
        region["startColumn"] = finding.column_start + 1
    if finding.column_end is not None:
        region["endColumn"] = finding.column_end + 1

    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": level,
        "message": {
            "text": finding.description or finding.title,
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": uri_path,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": region,
                }
            }
        ],
        "fingerprints": {
            "entropy/v1": finding.fingerprint,
        },
        "partialFingerprints": {
            "primaryLocationLineHash": finding.fingerprint,
        },
        "properties": {
            "findingId": finding.id,
            "category": finding.category.value,
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "impact": finding.impact,
            "recommendation": finding.recommendation,
        },
    }

    return result


def generate_sarif_log(
    scan: RepositoryScanResult,
    findings: list[Finding] | None = None,
) -> dict[str, Any]:
    """Generate a complete SARIF 2.1.0 JSON-serializable log dict from a scan result."""
    actual_findings = findings if findings is not None else scan.findings

    # Build unique rules metadata for the tool driver
    rules_dict: dict[str, dict[str, Any]] = {}
    for f in actual_findings:
        if f.rule_id not in rules_dict:
            rules_dict[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {
                    "text": f.title,
                },
                "fullDescription": {
                    "text": f.description,
                },
                "help": {
                    "text": f"{f.recommendation}\n\nImpact: {f.impact}",
                },
                "properties": {
                    "category": f.category.value,
                    "defaultSeverity": f.severity.value,
                },
            }

    # Sort rules deterministically by ruleId
    rules_list = [rules_dict[r_id] for r_id in sorted(rules_dict.keys())]

    # Convert findings deterministically sorted by file, line_start, line_end, id
    sorted_findings = sorted(
        actual_findings,
        key=lambda f: (f.file, f.line_start, f.line_end, f.id),
    )
    sarif_results = [finding_to_sarif_result(f) for f in sorted_findings]

    sarif_log: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": settings.APP_NAME,
                        "version": settings.VERSION,
                        "informationUri": "https://github.com/naveens-prog/Entropy",
                        "rules": rules_list,
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return sarif_log

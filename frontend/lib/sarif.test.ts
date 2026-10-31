import { describe, it, expect } from "vitest";
import { generateSarif, mapSeverityToSarifLevel } from "./sarif";
import { Finding, RepositoryScanResult } from "@/types";

describe("SARIF 2.1.0 Generator", () => {
  it("correctly maps severities to SARIF levels", () => {
    expect(mapSeverityToSarifLevel("critical")).toBe("error");
    expect(mapSeverityToSarifLevel("high")).toBe("error");
    expect(mapSeverityToSarifLevel("medium")).toBe("warning");
    expect(mapSeverityToSarifLevel("low")).toBe("note");
    expect(mapSeverityToSarifLevel("info")).toBe("note");
  });

  it("builds a valid OASIS SARIF 2.1.0 structure from findings", () => {
    const mockScan: RepositoryScanResult = {
      scan_id: "scan-test-123",
      repo_name: "test-repo",
      repo_path: "/workspace/test-repo",
      status: "completed",
      started_at: "2026-10-31T12:00:00Z",
      completed_at: "2026-10-31T12:01:00Z",
    };

    const mockFindings: Finding[] = [
      {
        id: "f-1",
        category: "authentication_consistency",
        rule_id: "ENT-AUTH-001",
        severity: "critical",
        confidence: "high",
        file: "backend/app/api/auth.py",
        line_start: 42,
        line_end: 45,
        title: "Unprotected Endpoint",
        description: "Missing authentication guard on sensitive handler",
        impact: "Unauthorized execution possible",
        recommendation: "Add Depends(verify_api_key)",
        fingerprint: "sha256-abc-123",
        evidence: {
          content: "@router.post('/delete')\ndef delete_all():",
          line_start: 42,
          line_end: 45,
          highlight_lines: [42],
        },
      },
      {
        id: "f-2",
        category: "architectural_consistency",
        rule_id: "ENT-ARCH-001",
        severity: "medium",
        confidence: "medium",
        file: "backend/app/services/session.py",
        line_start: 12,
        line_end: 12,
        title: "Circular Module Dependency",
        description: "Circular import between auth and session",
        impact: "Import race condition",
        recommendation: "Extract common types to shared module",
        fingerprint: "sha256-def-456",
        evidence: {
          content: "from app.services.auth import get_auth_token",
          line_start: 12,
          line_end: 12,
          highlight_lines: [12],
        },
      },
    ];

    const sarif = generateSarif(mockScan, mockFindings, null);

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toContain("sarif-schema-2.1.0.json");
    expect(sarif.runs.length).toBe(1);

    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe("Entropy");
    expect(run.tool.driver.rules.length).toBe(2);
    expect(run.results.length).toBe(2);

    const r1 = run.results[0];
    expect(r1.ruleId).toBe("ENT-AUTH-001");
    expect(r1.level).toBe("error");
    expect(r1.locations[0].physicalLocation.artifactLocation.uri).toBe("backend/app/api/auth.py");
    expect(r1.locations[0].physicalLocation.region?.startLine).toBe(42);

    const r2 = run.results[1];
    expect(r2.ruleId).toBe("ENT-ARCH-001");
    expect(r2.level).toBe("warning");

    // Verify originalUriBaseIds OASIS standard compliance
    expect(run.originalUriBaseIds).toBeDefined();
    expect(run.originalUriBaseIds?.["%SRCROOT%"]?.uri).toBe("file:///");

    // Verify rich rule help with markdown
    const rule1 = run.tool.driver.rules[0];
    expect(rule1.help?.markdown).toContain("### Unprotected Endpoint");
    expect(rule1.help?.markdown).toContain("Depends(verify_api_key)");
  });

  it("handles Windows absolute paths and edge line boundaries", () => {
    const mockScan: RepositoryScanResult = {
      scan_id: "scan-win",
      repo_name: "win-repo",
      repo_path: "C:\\projects\\win-repo",
      status: "completed",
      started_at: "2026-10-31T10:00:00Z",
    };

    const mockFinding: Finding = {
      id: "f-win",
      category: "logging_and_secrets",
      rule_id: "ENT-SEC-001",
      severity: "critical",
      confidence: "high",
      file: "C:\\projects\\win-repo\\src\\config.ts",
      line_start: 0,
      line_end: 0,
      title: "Hardcoded Secret",
      description: "Secret found in config",
      impact: "High",
      recommendation: "Use env var",
      fingerprint: "sha256-win",
      evidence: { content: "const key = '123';", line_start: 1, line_end: 1, highlight_lines: [1] },
    };

    const sarif = generateSarif(mockScan, [mockFinding], null);
    const result = sarif.runs[0].results[0];
    expect(result.locations[0].physicalLocation.artifactLocation.uri).toBe("projects/win-repo/src/config.ts");
    expect(result.locations[0].physicalLocation.region?.startLine).toBe(1);
  });
});

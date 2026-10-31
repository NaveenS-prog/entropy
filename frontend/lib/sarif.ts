import { Finding, RepositoryScanResult, DebtScoreResult, Severity } from "@/types";

/**
 * OASIS Static Analysis Results Interchange Format (SARIF) v2.1.0 Interfaces
 * Conforms strictly to OASIS Standard SARIF 2.1.0
 * Schema: https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json
 */

export interface SarifArtifactLocation {
  uri: string;
  uriBaseId?: string;
}

export interface SarifRegion {
  startLine: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
  snippet?: {
    text: string;
  };
}

export interface SarifPhysicalLocation {
  artifactLocation: SarifArtifactLocation;
  region?: SarifRegion;
}

export interface SarifLocation {
  physicalLocation: SarifPhysicalLocation;
}

export interface SarifRuleDescription {
  text: string;
}

export interface SarifReportingDescriptor {
  id: string;
  name?: string;
  shortDescription?: SarifRuleDescription;
  fullDescription?: SarifRuleDescription;
  help?: {
    text: string;
    markdown?: string;
  };
  defaultConfiguration?: {
    level: "error" | "warning" | "note" | "none";
  };
  helpUri?: string;
  properties?: Record<string, unknown>;
}

export interface SarifResult {
  ruleId: string;
  ruleIndex?: number;
  level: "error" | "warning" | "note" | "none";
  message: {
    text: string;
  };
  locations: SarifLocation[];
  properties?: {
    category?: string;
    confidence?: string;
    impact?: string;
    recommendation?: string;
    fingerprint?: string;
  };
}

export interface SarifToolComponent {
  name: string;
  version: string;
  semanticVersion?: string;
  informationUri: string;
  organization?: string;
  rules: SarifReportingDescriptor[];
}

export interface SarifRun {
  tool: {
    driver: SarifToolComponent;
  };
  results: SarifResult[];
  originalUriBaseIds?: Record<
    string,
    {
      uri: string;
      description?: {
        text: string;
      };
    }
  >;
  invocations?: Array<{
    executionSuccessful: boolean;
    endTimeUtc?: string;
    startTimeUtc?: string;
  }>;
  properties?: {
    scanId?: string;
    entropyScore?: number;
    tier?: string;
    repoName?: string;
    branch?: string;
    commitHash?: string;
  };
}

export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: SarifRun[];
}

/**
 * Maps Entropy severity to SARIF 2.1.0 level
 */
export function mapSeverityToSarifLevel(
  severity: Severity
): "error" | "warning" | "note" | "none" {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
    case "info":
      return "note";
    default:
      return "warning";
  }
}

/**
 * Formats a rule ID into a valid SARIF rule identifier
 */
export function formatRuleName(title: string): string {
  return title
    .replace(/[^a-zA-Z0-9]/g, " ")
    .split(" ")
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
    .join("");
}

/**
 * Builds an OASIS SARIF 2.1.0 log document from Entropy scan data
 */
export function generateSarif(
  scan: RepositoryScanResult,
  findings: Finding[],
  score?: DebtScoreResult | null
): SarifLog {
  const ruleMap = new Map<string, SarifReportingDescriptor>();

  findings.forEach((finding) => {
    if (!ruleMap.has(finding.rule_id)) {
      ruleMap.set(finding.rule_id, {
        id: finding.rule_id,
        name: formatRuleName(finding.title),
        shortDescription: {
          text: finding.title,
        },
        fullDescription: {
          text: finding.description || finding.title,
        },
        help: {
          text: `${finding.description}\n\nRemediation:\n${finding.recommendation || "Follow architectural best practices."}`,
          markdown: `### ${finding.title}\n\n${finding.description}\n\n**Impact:** ${finding.impact || "N/A"}\n\n**Remediation:**\n${finding.recommendation || "Follow architectural best practices."}`,
        },
        defaultConfiguration: {
          level: mapSeverityToSarifLevel(finding.severity),
        },
        helpUri: `https://github.com/NaveenS-prog/entropy/blob/main/docs/rules/${finding.rule_id}.md`,
        properties: {
          category: finding.category,
          defaultSeverity: finding.severity,
          impact: finding.impact,
          recommendation: finding.recommendation,
        },
      });
    }
  });

  const ruleList = Array.from(ruleMap.values());
  const ruleIdToIndex = new Map<string, number>();
  ruleList.forEach((rule, idx) => ruleIdToIndex.set(rule.id, idx));

  const results: SarifResult[] = findings.map((f) => {
    const normPath = f.file
      .replace(/^[a-zA-Z]:[\\/]/, "")
      .replace(/\\/g, "/")
      .replace(/^\/+/, "");
    return {
      ruleId: f.rule_id,
      ruleIndex: ruleIdToIndex.get(f.rule_id),
      level: mapSeverityToSarifLevel(f.severity),
      message: {
        text: `${f.title}: ${f.description}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: normPath,
              uriBaseId: "%SRCROOT%",
            },
            region: {
              startLine: Math.max(1, f.line_start),
              endLine: Math.max(f.line_start, f.line_end || f.line_start),
              snippet: f.evidence?.content
                ? {
                    text: f.evidence.content,
                  }
                : undefined,
            },
          },
        },
      ],
      properties: {
        category: f.category,
        confidence: f.confidence,
        impact: f.impact,
        recommendation: f.recommendation,
        fingerprint: f.fingerprint,
      },
    };
  });

  const sarifLog: SarifLog = {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Entropy",
            version: "0.1.0",
            semanticVersion: "0.1.0",
            informationUri: "https://github.com/NaveenS-prog/entropy",
            organization: "Entropy Engineering",
            rules: ruleList,
          },
        },
        originalUriBaseIds: {
          "%SRCROOT%": {
            uri: "file:///",
            description: {
              text: "The root directory of the analyzed repository source tree.",
            },
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: scan.status !== "failed",
            startTimeUtc: scan.started_at,
            endTimeUtc: scan.completed_at || new Date().toISOString(),
          },
        ],
        properties: {
          scanId: scan.scan_id,
          entropyScore: score?.total_score ?? scan.score?.total_score,
          tier: score?.tier ?? scan.score?.tier,
          repoName: scan.repository?.name || scan.repo_name || "Repository",
          branch: scan.repository?.branch || scan.branch || undefined,
          commitHash: scan.repository?.commit_hash || scan.commit_hash || undefined,
        },
      },
    ],
  };

  return sarifLog;
}

/**
 * Triggers a client-side browser download of the generated SARIF file
 */
export function downloadSarifFile(
  scan: RepositoryScanResult,
  findings: Finding[],
  score?: DebtScoreResult | null
): void {
  const sarif = generateSarif(scan, findings, score);
  const jsonString = JSON.stringify(sarif, null, 2);
  const blob = new Blob([jsonString], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const scanShort = (scan.scan_id || "scan").slice(0, 8);
  const repoSlug = (scan.repository?.name || scan.repo_name || "repo")
    .replace(/[^a-zA-Z0-9_-]/g, "_")
    .toLowerCase();
  a.href = url;
  a.download = `entropy-${repoSlug}-${scanShort}.sarif`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

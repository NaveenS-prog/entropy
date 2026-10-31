import {
  AIExplanation,
  DebtScoreResult,
  Finding,
  FindingExplanation,
  PaginatedScanSnapshots,
  PolicyConfig,
  PolicyEvaluation,
  PRAnalysisRecord,
  PRAnalysisTriggerRequest,
  RefactoringSuggestion,
  RepositoryManifest,
  RepositoryScanResult,
  RepositoryTrendResponse,
  RuleDefinition,
  ScanComparisonResult,
  SystemHealth,
} from "@/types";
import { DEMO_AI_EXPLANATIONS } from "./demoData";


const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";
const API_KEY = process.env.NEXT_PUBLIC_API_KEY;

function getHeaders(customHeaders: Record<string, string> = {}): Record<string, string> {
  const headers: Record<string, string> = { ...customHeaders };
  if (API_KEY) {
    headers["X-API-Key"] = API_KEY;
  }
  return headers;
}

export async function fetchHealth(): Promise<SystemHealth> {
  const res = await fetch(`${API_BASE}/health`, { cache: "no-store", headers: getHeaders() });
  if (!res.ok) throw new Error(`Health check failed: ${res.statusText}`);
  return res.json();
}

export async function listScans(): Promise<RepositoryScanResult[]> {
  const res = await fetch(`${API_BASE}/scans`, { cache: "no-store", headers: getHeaders() });
  if (!res.ok) throw new Error(`Failed to list scans: ${res.statusText}`);
  return res.json();
}

export async function getScan(scanId: string): Promise<RepositoryScanResult> {
  const res = await fetch(`${API_BASE}/scans/${scanId}`, { cache: "no-store", headers: getHeaders() });
  if (!res.ok) throw new Error(`Failed to fetch scan ${scanId}: ${res.statusText}`);
  return res.json();
}

export async function getManifest(scanId: string): Promise<RepositoryManifest> {
  const res = await fetch(`${API_BASE}/scans/${scanId}/manifest`, { cache: "no-store", headers: getHeaders() });
  if (!res.ok) throw new Error(`Failed to fetch manifest for scan ${scanId}: ${res.statusText}`);
  return res.json();
}

export async function getFindings(scanId: string): Promise<Finding[]> {
  const res = await fetch(`${API_BASE}/scans/${scanId}/findings`, { cache: "no-store", headers: getHeaders() });
  if (!res.ok) throw new Error(`Failed to fetch findings for scan ${scanId}: ${res.statusText}`);
  return res.json();
}

export async function getScore(scanId: string): Promise<DebtScoreResult> {
  const res = await fetch(`${API_BASE}/scans/${scanId}/score`, { cache: "no-store", headers: getHeaders() });
  if (!res.ok) throw new Error(`Failed to fetch score for scan ${scanId}: ${res.statusText}`);
  return res.json();
}

export async function triggerScan(repoPath: string, repoName?: string): Promise<RepositoryScanResult> {
  const res = await fetch(`${API_BASE}/repositories/scan`, {
    method: "POST",
    headers: getHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ path: repoPath, repo_name: repoName }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Scan failed: ${res.statusText}`);
  }
  return res.json();
}

export async function uploadAndScanArchive(
  archiveBlob: Blob,
  fileName: string,
  repoName?: string,
  includeTests: boolean = false
): Promise<RepositoryScanResult> {
  const formData = new FormData();
  formData.append("file", archiveBlob, fileName);
  if (repoName) {
    formData.append("repo_name", repoName);
  }
  formData.append("include_tests", String(includeTests));

  const headers = getHeaders();
  delete headers["Content-Type"];

  const res = await fetch(`${API_BASE}/repositories/upload`, {
    method: "POST",
    headers,
    body: formData,
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Upload scan failed: ${res.statusText}`);
  }
  return res.json();
}

export async function explainFinding(
  scanId: string,
  findingId: string
): Promise<FindingExplanation> {
  if (scanId === "demo-forensic-scan-01" || findingId.startsWith("finding-demo-")) {
    const demo = DEMO_AI_EXPLANATIONS[findingId];
    if (demo) {
      return {
        finding_id: findingId,
        architectural_context: demo.summary,
        maintenance_risk: demo.architectural_impact,
        suggested_action: demo.remediation,
      };
    }
  }

  try {
    const res = await fetch(`${API_BASE}/scans/${scanId}/findings/${findingId}/explain`, {
      cache: "no-store",
      headers: getHeaders(),
    });
    if (!res.ok) {
      const demo = DEMO_AI_EXPLANATIONS[findingId];
      if (demo) {
        return {
          finding_id: findingId,
          architectural_context: demo.summary,
          maintenance_risk: demo.architectural_impact,
          suggested_action: demo.remediation,
        };
      }
      throw new Error(`Failed to get explanation: ${res.statusText}`);
    }
    return res.json();
  } catch (err: unknown) {
    const demo = DEMO_AI_EXPLANATIONS[findingId];
    if (demo) {
      return {
        finding_id: findingId,
        architectural_context: demo.summary,
        maintenance_risk: demo.architectural_impact,
        suggested_action: demo.remediation,
      };
    }
    throw err;
  }
}

export async function getRefactoringSuggestion(
  scanId: string,
  findingId: string
): Promise<RefactoringSuggestion> {
  if (scanId === "demo-forensic-scan-01" || findingId.startsWith("finding-demo-")) {
    const demo = DEMO_AI_EXPLANATIONS[findingId];
    if (demo) {
      return {
        finding_id: findingId,
        before_code: "// Original AST fragment flagged by rule",
        suggested_code: demo.suggested_pattern,
        rationale: demo.summary,
      };
    }
  }

  try {
    const res = await fetch(`${API_BASE}/scans/${scanId}/findings/${findingId}/refactor`, {
      cache: "no-store",
      headers: getHeaders(),
    });
    if (!res.ok) {
      const demo = DEMO_AI_EXPLANATIONS[findingId];
      if (demo) {
        return {
          finding_id: findingId,
          before_code: "// Original AST fragment flagged by rule",
          suggested_code: demo.suggested_pattern,
          rationale: demo.summary,
        };
      }
      throw new Error(`Failed to get refactoring suggestion: ${res.statusText}`);
    }
    return res.json();
  } catch (err: unknown) {
    const demo = DEMO_AI_EXPLANATIONS[findingId];
    if (demo) {
      return {
        finding_id: findingId,
        before_code: "// Original AST fragment flagged by rule",
        suggested_code: demo.suggested_pattern,
        rationale: demo.summary,
      };
    }
    throw err;
  }
}

export async function listRules(): Promise<RuleDefinition[]> {
  const res = await fetch(`${API_BASE}/analyzers/rules`, { cache: "no-store", headers: getHeaders() });
  if (!res.ok) throw new Error(`Failed to list rules: ${res.statusText}`);
  return res.json();
}

export async function requestAIExplanation(
  findingId: string,
  scanId?: string
): Promise<AIExplanation> {
  if (scanId === "demo-forensic-scan-01" || findingId.startsWith("finding-demo-")) {
    const demo = DEMO_AI_EXPLANATIONS[findingId];
    if (demo) {
      return demo;
    }
  }

  const url = scanId
    ? `${API_BASE}/scans/${scanId}/findings/${findingId}/explanation`
    : `${API_BASE}/findings/${findingId}/explanation`;

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: getHeaders({ "Content-Type": "application/json" }),
    });
    if (!res.ok) {
      const demo = DEMO_AI_EXPLANATIONS[findingId];
      if (demo) {
        return demo;
      }
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `Failed to generate AI explanation: ${res.statusText}`);
    }
    return res.json();
  } catch (err: unknown) {
    const demo = DEMO_AI_EXPLANATIONS[findingId];
    if (demo) {
      return demo;
    }
    throw err;
  }
}


export async function listRepositoryScans(
  repositoryId: string,
  page: number = 1,
  pageSize: number = 20,
  status?: string,
  branch?: string
): Promise<PaginatedScanSnapshots> {
  const params = new URLSearchParams({
    page: String(page),
    page_size: String(pageSize),
  });
  if (status) params.set("status", status);
  if (branch) params.set("branch", branch);

  const res = await fetch(`${API_BASE}/repositories/${repositoryId}/scans?${params.toString()}`, {
    cache: "no-store",
    headers: getHeaders(),
  });
  if (!res.ok) throw new Error(`Failed to list repository scans: ${res.statusText}`);
  return res.json();
}

export async function getRepositoryTrend(
  repositoryId: string
): Promise<RepositoryTrendResponse> {
  const res = await fetch(`${API_BASE}/repositories/${repositoryId}/trend`, {
    cache: "no-store",
    headers: getHeaders(),
  });
  if (!res.ok) throw new Error(`Failed to fetch repository trend: ${res.statusText}`);
  return res.json();
}

export async function compareScans(
  currentScanId: string,
  previousScanId: string
): Promise<ScanComparisonResult> {
  const res = await fetch(`${API_BASE}/scans/${currentScanId}/compare/${previousScanId}`, {
    cache: "no-store",
    headers: getHeaders(),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Comparison failed: ${res.statusText}`);
  }
  return res.json();
}

export async function getPRAnalysis(
  owner: string,
  repo: string,
  prNumber: number
): Promise<PRAnalysisRecord> {
  const res = await fetch(`${API_BASE}/github/prs/${owner}/${repo}/${prNumber}`, {
    cache: "no-store",
    headers: getHeaders(),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to fetch PR analysis: ${res.statusText}`);
  }
  return res.json();
}

export async function getPRComparison(
  owner: string,
  repo: string,
  prNumber: number
): Promise<ScanComparisonResult> {
  const res = await fetch(`${API_BASE}/github/prs/${owner}/${repo}/${prNumber}/comparison`, {
    cache: "no-store",
    headers: getHeaders(),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to fetch PR comparison: ${res.statusText}`);
  }
  return res.json();
}

export async function triggerPRAnalysis(
  owner: string,
  repo: string,
  prNumber: number,
  request?: PRAnalysisTriggerRequest
): Promise<PRAnalysisRecord> {
  const res = await fetch(`${API_BASE}/github/prs/${owner}/${repo}/${prNumber}/analyze`, {
    method: "POST",
    headers: getHeaders({ "Content-Type": "application/json" }),
    body: request ? JSON.stringify(request) : JSON.stringify({}),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to trigger PR analysis: ${res.statusText}`);
  }
  return res.json();
}

export async function listPRAnalyses(
  owner: string,
  repo: string,
  limit: number = 20
): Promise<PRAnalysisRecord[]> {
  const res = await fetch(`${API_BASE}/github/prs/${owner}/${repo}?limit=${limit}`, {
    cache: "no-store",
    headers: getHeaders(),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to list PR analyses: ${res.statusText}`);
  }
  return res.json();
}

export async function getDefaultPolicy(): Promise<PolicyConfig> {
  const res = await fetch(`${API_BASE}/policies/default`, { cache: "no-store", headers: getHeaders() });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to fetch default policy: ${res.statusText}`);
  }
  return res.json();
}

export async function validatePolicy(
  policy: Partial<PolicyConfig>
): Promise<{ valid: boolean; policy?: PolicyConfig; errors: any[] }> {
  const res = await fetch(`${API_BASE}/policies/validate`, {
    method: "POST",
    headers: getHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(policy),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to validate policy: ${res.statusText}`);
  }
  return res.json();
}

export async function evaluateScanPolicy(
  scanId: string,
  customPolicy?: Partial<PolicyConfig>
): Promise<PolicyEvaluation> {
  const res = await fetch(`${API_BASE}/policies/scans/${scanId}/evaluate`, {
    method: "POST",
    headers: getHeaders({ "Content-Type": "application/json" }),
    body: customPolicy ? JSON.stringify(customPolicy) : undefined,
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to evaluate scan policy: ${res.statusText}`);
  }
  return res.json();
}

export async function evaluateComparisonPolicy(
  currentScanId: string,
  previousScanId: string,
  customPolicy?: Partial<PolicyConfig>
): Promise<PolicyEvaluation> {
  const res = await fetch(
    `${API_BASE}/policies/scans/${currentScanId}/compare/${previousScanId}/evaluate`,
    {
      method: "POST",
      headers: getHeaders({ "Content-Type": "application/json" }),
      body: customPolicy ? JSON.stringify(customPolicy) : undefined,
    }
  );
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to evaluate comparison policy: ${res.statusText}`);
  }
  return res.json();
}

export async function getPRPolicy(analysisId: string): Promise<PolicyEvaluation> {
  const res = await fetch(`${API_BASE}/policies/github/prs/${analysisId}/policy`, {
    cache: "no-store",
    headers: getHeaders(),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to fetch PR policy: ${res.statusText}`);
  }
  return res.json();
}

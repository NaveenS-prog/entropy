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
  RepositoryManifest,
  RepositoryScanResult,
  RepositoryTrendResponse,
  RuleDefinition,
  ScanComparisonResult,
  SystemHealth,
} from "@/types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

export async function fetchHealth(): Promise<SystemHealth> {
  const res = await fetch(`${API_BASE}/health`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Health check failed: ${res.statusText}`);
  return res.json();
}

export async function listScans(): Promise<RepositoryScanResult[]> {
  const res = await fetch(`${API_BASE}/scans`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to list scans: ${res.statusText}`);
  return res.json();
}

export async function getScan(scanId: string): Promise<RepositoryScanResult> {
  const res = await fetch(`${API_BASE}/scans/${scanId}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to fetch scan ${scanId}: ${res.statusText}`);
  return res.json();
}

export async function getManifest(scanId: string): Promise<RepositoryManifest> {
  const res = await fetch(`${API_BASE}/scans/${scanId}/manifest`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to fetch manifest for scan ${scanId}: ${res.statusText}`);
  return res.json();
}

export async function getFindings(scanId: string): Promise<Finding[]> {
  const res = await fetch(`${API_BASE}/scans/${scanId}/findings`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to fetch findings for scan ${scanId}: ${res.statusText}`);
  return res.json();
}

export async function getScore(scanId: string): Promise<DebtScoreResult> {
  const res = await fetch(`${API_BASE}/scans/${scanId}/score`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to fetch score for scan ${scanId}: ${res.statusText}`);
  return res.json();
}

export async function triggerScan(repoPath: string, repoName?: string): Promise<RepositoryScanResult> {
  const res = await fetch(`${API_BASE}/repositories/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ path: repoPath, repo_name: repoName }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Scan failed: ${res.statusText}`);
  }
  return res.json();
}


export async function explainFinding(
  scanId: string,
  findingId: string
): Promise<FindingExplanation> {
  const res = await fetch(`${API_BASE}/scans/${scanId}/findings/${findingId}/explain`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`Failed to get explanation: ${res.statusText}`);
  return res.json();
}

export async function listRules(): Promise<RuleDefinition[]> {
  const res = await fetch(`${API_BASE}/analyzers/rules`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to list rules: ${res.statusText}`);
  return res.json();
}

export async function requestAIExplanation(
  findingId: string,
  scanId?: string
): Promise<AIExplanation> {
  const url = scanId
    ? `${API_BASE}/scans/${scanId}/findings/${findingId}/explanation`
    : `${API_BASE}/findings/${findingId}/explanation`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to generate AI explanation: ${res.statusText}`);
  }
  return res.json();
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
  });
  if (!res.ok) throw new Error(`Failed to list repository scans: ${res.statusText}`);
  return res.json();
}

export async function getRepositoryTrend(
  repositoryId: string
): Promise<RepositoryTrendResponse> {
  const res = await fetch(`${API_BASE}/repositories/${repositoryId}/trend`, {
    cache: "no-store",
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
    headers: { "Content-Type": "application/json" },
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
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to list PR analyses: ${res.statusText}`);
  }
  return res.json();
}

export async function getDefaultPolicy(): Promise<PolicyConfig> {
  const res = await fetch(`${API_BASE}/policies/default`, { cache: "no-store" });
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
    headers: { "Content-Type": "application/json" },
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
    headers: { "Content-Type": "application/json" },
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
      headers: { "Content-Type": "application/json" },
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
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to fetch PR policy: ${res.statusText}`);
  }
  return res.json();
}




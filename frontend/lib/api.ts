import {
  AIExplanation,
  DebtScoreResult,
  Finding,
  FindingExplanation,
  RepositoryManifest,
  RepositoryScanResult,
  RuleDefinition,
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


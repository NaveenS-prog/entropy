/**
 * SilentGuard TypeScript Domain Types
 * Strictly aligned with Backend Pydantic Domain Models
 */

export type DebtCategory =
  | "error_handling"
  | "authentication_consistency"
  | "authorization_consistency"
  | "input_validation"
  | "logging_and_secrets"
  | "code_duplication"
  | "architectural_consistency";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type Confidence = "low" | "medium" | "high";

export type DebtScoreTier = "very_low" | "low" | "moderate" | "high" | "very_high";

export type ScanStatus =
  | "queued"
  | "ingesting"
  | "parsing"
  | "analyzing"
  | "scoring"
  | "completed"
  | "failed";

export interface CodeEvidence {
  content: string;
  line_start: number;
  line_end: number;
  highlight_lines: number[];
}

export interface Finding {
  id: string;
  category: DebtCategory;
  rule_id: string;
  severity: Severity;
  confidence: Confidence;
  file: string;
  line_start: number;
  line_end: number;
  symbol?: string | null;
  title: string;
  description: string;
  evidence: CodeEvidence;
  impact: string;
  recommendation: string;
  fingerprint: string;
  metadata?: Record<string, unknown>;
}

export interface CategoryScoreBreakdown {
  category: DebtCategory;
  score: number;
  finding_count: number;
  severity_counts: Record<Severity, number>;
  weight: number;
  weighted_score: number;
  raw_deduction: number;
  explanation: string;
}

export interface DebtScoreResult {
  total_score: number;
  tier: DebtScoreTier;
  category_scores: Record<DebtCategory, CategoryScoreBreakdown>;
  total_findings: number;
  total_loc: number;
  analyzed_files: number;
  skipped_files: number;
  formula_summary: string;
  audit_trail: string[];
  is_explainable: boolean;
}

export interface RepositoryMetadata {
  name: string;
  path: string;
  branch?: string | null;
  commit_hash?: string | null;
  total_files: number;
  scannable_files: number;
  total_loc: number;
}

export interface RepositoryScanResult {
  scan_id: string;
  repository: RepositoryMetadata;
  status: ScanStatus;
  findings: Finding[];
  score?: DebtScoreResult | null;
  started_at: string;
  completed_at?: string | null;
  duration_ms?: number | null;
  analyzers_executed: string[];
  errors: string[];
}

export interface FindingExplanation {
  finding_id: string;
  architectural_context: string;
  maintenance_risk: string;
  suggested_action: string;
}

export interface RuleDefinition {
  rule_id: string;
  category: DebtCategory;
  title: string;
  description: string;
  default_severity: Severity;
  default_confidence: Confidence;
  languages: string[];
  impact_template: string;
  recommendation_template: string;
}

export interface SystemHealth {
  status: string;
  service: string;
  version: string;
  active_analyzers_count: number;
  total_rules_count: number;
  supported_languages: string[];
}

/**
 * Entropy TypeScript Domain Types
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
  | "pending"
  | "scanning"
  | "queued"
  | "ingesting"
  | "parsing"
  | "analyzing"
  | "scoring"
  | "completed"
  | "failed";

export type SupportedLanguage =
  | "python"
  | "javascript"
  | "typescript"
  | "java"
  | "c"
  | "cpp"
  | "go"
  | "rust"
  | "unknown";

export interface SourceFileMetadata {
  path: string;
  language: string;
  size: number;
  line_count?: number | null;
  analysis_supported: boolean;
  skip_reason?: string | null;
}

export interface SkippedFileRecord {
  path: string;
  size: number;
  reason: string;
}

export interface DirectoryNode {
  name: string;
  path: string;
  type: "directory" | "file";
  size: number;
  children: DirectoryNode[];
}

export interface RepositoryManifestSummary {
  name: string;
  path: string;
  scan_timestamp: string;
  total_files: number;
  source_files: number;
  ignored_files: number;
  skipped_files: number;
  total_source_size: number;
  total_source_loc: number;
}

export interface RepositoryManifest {
  repository: RepositoryManifestSummary;
  languages: Record<string, number>;
  files: SourceFileMetadata[];
  skipped_files: SkippedFileRecord[];
  directory_structure?: DirectoryNode | null;
}

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

export type CategoryAnalysisStatus = "analyzed" | "not_analyzed";

export interface RuleContribution {
  rule_id: string;
  rule_title: string;
  finding_count: number;
  weighted_points: number;
}

export interface NormalizationMetrics {
  total_loc: number;
  analyzed_files: number;
  kloc: number;
  scale_factor: number;
  formula: string;
}

export interface CategoryScoreBreakdown {
  category: DebtCategory;
  status: CategoryAnalysisStatus;
  score: number | null;
  finding_count: number;
  severity_counts: Record<Severity, number>;
  weight: number;
  weighted_score: number;
  raw_deduction: number;
  normalized_penalty?: number;
  explanation: string;
  top_rules?: RuleContribution[];
}

export interface DebtScoreResult {
  total_score: number;
  entropy_score?: number;
  tier: DebtScoreTier;
  status?: string;
  analyzed_categories?: DebtCategory[];
  category_scores: Record<DebtCategory, CategoryScoreBreakdown>;
  total_findings: number;
  total_loc: number;
  analyzed_files: number;
  skipped_files: number;
  severity_breakdown?: Record<Severity, number>;
  top_contributing_rules?: RuleContribution[];
  normalization?: NormalizationMetrics | null;
  formula_summary: string;
  audit_trail: string[];
  is_explainable: boolean;
  disclaimer?: string;
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
  manifest?: RepositoryManifest | null;
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

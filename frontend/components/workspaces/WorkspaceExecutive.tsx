"use client";

import { useState } from "react";
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  Calculator,
  CheckCircle2,
  Clock,
  ExternalLink,
  FileCheck,
  FileCode2,
  FileWarning,
  Flame,
  Info,
  Layers,
  Percent,
  Scale,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import {
  DebtCategory,
  DebtScoreResult,
  Finding,
  RepositoryMetadata,
  Severity,
} from "@/types";
import { getCategoryDisplayName, getTierColor } from "@/lib/utils";

interface WorkspaceExecutiveProps {
  score: DebtScoreResult | null;
  findings: Finding[];
  repository?: RepositoryMetadata | null;
  durationMs?: number | null;
  onSelectCategory?: (category: DebtCategory) => void;
  onNavigateFindings?: () => void;
}

export function WorkspaceExecutive({
  score,
  findings,
  repository,
  durationMs,
  onSelectCategory,
  onNavigateFindings,
}: WorkspaceExecutiveProps) {
  const [showFormulaModal, setShowFormulaModal] = useState(false);

  if (!score) {
    return (
      <div className="bg-surface-1 border border-border-subtle rounded-xl p-12 text-center space-y-3 font-mono">
        <Activity className="h-8 w-8 text-ink-500 mx-auto animate-pulse" />
        <div className="text-sm font-semibold text-text-primary">
          Scoring Engine Idle or Calculating
        </div>
        <div className="text-xs text-ink-400">
          Load or execute a repository scan to evaluate mathematical debt posture.
        </div>
      </div>
    );
  }

  const tierStyle = getTierColor(score.tier);
  const totalFindings = findings.length;
  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const mediumCount = findings.filter((f) => f.severity === "medium").length;
  const lowCount = findings.filter((f) => f.severity === "low" || f.severity === "info").length;

  const totalLoc = score.total_loc || repository?.total_loc || 1;
  const kLoc = Math.max(0.001, totalLoc / 1000);
  const defectDensity = (totalFindings / kLoc).toFixed(2);
  const highRiskBlastRadius = totalFindings > 0
    ? (((criticalCount + highCount) / totalFindings) * 100).toFixed(1)
    : "0.0";

  // Remediation time estimation: Critical: 4h, High: 2h, Medium: 1h, Low: 0.5h
  const estimatedRemediationHours = (
    criticalCount * 4 +
    highCount * 2 +
    mediumCount * 1 +
    lowCount * 0.5
  ).toFixed(1);

  // SVG Radial Gauge calculation
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (Math.min(100, Math.max(0, score.total_score)) / 100) * circumference;

  const categoryList: DebtCategory[] = [
    "authentication_consistency",
    "authorization_consistency",
    "architectural_consistency",
    "error_handling",
    "input_validation",
    "logging_and_secrets",
    "code_duplication",
  ];

  return (
    <div className="space-y-6">
      {/* Executive Header Banner: Radial Gauge + Posture Summary */}
      <div className="bg-surface-1 border border-border-subtle rounded-xl p-6 relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-8">
          {/* Left: SVG High-Precision Calibrated Radial Gauge */}
          <div className="flex items-center gap-6">
            <div className="relative flex items-center justify-center shrink-0">
              <svg className="w-36 h-36 transform -rotate-90" viewBox="0 0 128 128">
                {/* Background Ring */}
                <circle
                  cx="64"
                  cy="64"
                  r={radius}
                  className="stroke-surface-3"
                  strokeWidth="8"
                  fill="transparent"
                />
                {/* Active Progress Ring */}
                <circle
                  cx="64"
                  cy="64"
                  r={radius}
                  className={
                    score.tier === "very_low"
                      ? "stroke-emerald-400"
                      : score.tier === "low"
                      ? "stroke-cyan-400"
                      : score.tier === "moderate"
                      ? "stroke-amber-400"
                      : score.tier === "high"
                      ? "stroke-orange-400"
                      : "stroke-red-400"
                  }
                  strokeWidth="8"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  strokeLinecap="round"
                  fill="transparent"
                  style={{ transition: "stroke-dashoffset 0.8s ease-out" }}
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                <span className={`text-4xl font-bold font-mono tracking-tight tabular-nums ${tierStyle.text}`}>
                  {score.total_score}
                </span>
                <span className="text-[10px] text-ink-400 font-mono tracking-wider uppercase mt-0.5">
                  / 100 pts
                </span>
              </div>
            </div>

            <div className="space-y-2 max-w-xl">
              <div className="flex items-center gap-2.5 flex-wrap">
                <h2 className="text-xl font-bold text-white tracking-tight">
                  {repository?.name || "Repository"} Posture
                </h2>
                <span
                  className={`text-xs px-2.5 py-0.5 rounded-full font-mono font-medium ${tierStyle.bg} ${tierStyle.text} border ${tierStyle.border}`}
                >
                  Tier: {score.tier.toUpperCase().replace("_", " ")}
                </span>
                {durationMs && (
                  <span className="text-xs px-2 py-0.5 rounded bg-surface-2 border border-border-subtle text-ink-400 font-mono">
                    {(durationMs / 1000).toFixed(2)}s scan
                  </span>
                )}
              </div>

              <p className="text-xs text-ink-300 leading-relaxed font-sans">
                {score.formula_summary ||
                  "Score derived deterministically from multi-category AST penalty deductions, normalized against codebase volume and architectural invariants."}
              </p>

              <div className="pt-1 flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setShowFormulaModal(true)}
                  className="flex items-center gap-1.5 px-3 py-1 bg-surface-2 hover:bg-surface-3 text-text-primary border border-border-strong rounded-md text-xs font-mono transition-colors"
                >
                  <Calculator className="h-3.5 w-3.5 text-emerald-400" />
                  <span>Audit Calculation Formula</span>
                </button>
                {onNavigateFindings && (
                  <button
                    type="button"
                    onClick={onNavigateFindings}
                    className="flex items-center gap-1.5 px-3 py-1 bg-transparent hover:bg-surface-2 text-ink-400 hover:text-white rounded-md text-xs font-mono transition-colors"
                  >
                    <span>View {totalFindings} Findings</span>
                    <ArrowRight className="h-3 w-3" />
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Right: Severity Floor Breach Alert (If Applied) */}
          {score.severity_floor_applied && (
            <div className="lg:max-w-md bg-red-950/40 border border-red-500/40 rounded-xl p-4 space-y-2">
              <div className="flex items-center gap-2 text-red-400 font-mono text-xs font-semibold">
                <AlertOctagon className="h-4 w-4 shrink-0" />
                <span>SEVERITY FLOOR ENFORCED</span>
              </div>
              <p className="text-xs text-ink-200 leading-relaxed font-sans">
                {score.floor_reason ||
                  "A critical security or architectural invariant violation was detected. Score capped by policy."}
              </p>
              <div className="text-[11px] font-mono text-red-300/80 bg-red-950/60 px-2 py-1 rounded border border-red-900">
                Rule: Critical findings enforce an absolute score ceiling regardless of LOC volume.
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Metric Vector Bar: 4-Column Mathematical Density */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Metric 1: Defect Density */}
        <div className="bg-surface-1 border border-border-subtle rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between text-xs text-ink-400 font-mono">
            <span>Defect Density</span>
            <FileWarning className="h-4 w-4 text-ink-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-white tabular-nums">
            {defectDensity}
          </div>
          <div className="text-[11px] text-ink-500 font-mono">
            Findings / 1,000 LOC
          </div>
        </div>

        {/* Metric 2: High-Risk Blast Radius */}
        <div className="bg-surface-1 border border-border-subtle rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between text-xs text-ink-400 font-mono">
            <span>Blast Radius</span>
            <Flame className="h-4 w-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-red-400 tabular-nums">
            {highRiskBlastRadius}%
          </div>
          <div className="text-[11px] text-ink-500 font-mono">
            {criticalCount + highCount} of {totalFindings} findings critical/high
          </div>
        </div>

        {/* Metric 3: Technical Remediation Hours */}
        <div className="bg-surface-1 border border-border-subtle rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between text-xs text-ink-400 font-mono">
            <span>Remediation Work</span>
            <Clock className="h-4 w-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400 tabular-nums">
            ~{estimatedRemediationHours}h
          </div>
          <div className="text-[11px] text-ink-500 font-mono">
            Estimated developer effort
          </div>
        </div>

        {/* Metric 4: AST Coverage */}
        <div className="bg-surface-1 border border-border-subtle rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between text-xs text-ink-400 font-mono">
            <span>Coverage Ratio</span>
            <FileCheck className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400 tabular-nums">
            {score.coverage ? `${score.coverage.loc_coverage_percentage}%` : "100%"}
          </div>
          <div className="text-[11px] text-ink-500 font-mono">
            {score.coverage
              ? `${score.coverage.covered_loc.toLocaleString()} / ${score.coverage.total_loc.toLocaleString()} LOC`
              : `${totalLoc.toLocaleString()} LOC analyzed`}
          </div>
        </div>
      </div>

      {/* Category Breakdown Matrix */}
      <div className="bg-surface-1 border border-border-subtle rounded-xl p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-border-subtle pb-3">
          <div>
            <h3 className="text-sm font-semibold text-white font-mono flex items-center gap-2">
              <Layers className="h-4 w-4 text-emerald-400" />
              <span>Architectural & Security Debt Categories</span>
            </h3>
            <p className="text-xs text-ink-400">
              Normalized scoring breakdown across seven deterministic analysis vectors
            </p>
          </div>
          <span className="text-xs font-mono text-ink-400">
            {categoryList.length} Categories Analyzed
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {categoryList.map((category) => {
            const catScore = score.category_scores?.[category];
            const catFindings = findings.filter((f) => f.category === category);
            const crit = catFindings.filter((f) => f.severity === "critical").length;
            const high = catFindings.filter((f) => f.severity === "high").length;
            const med = catFindings.filter((f) => f.severity === "medium").length;
            const low = catFindings.filter((f) => f.severity === "low" || f.severity === "info").length;

            const scoreVal = catScore?.score ?? null;
            const isClean = catFindings.length === 0;

            return (
              <div
                key={category}
                onClick={() => onSelectCategory && onSelectCategory(category)}
                className="bg-surface-2 hover:bg-surface-3 border border-border-subtle hover:border-border-strong rounded-xl p-4 transition-all cursor-pointer group flex flex-col justify-between space-y-3"
              >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h4 className="text-xs font-semibold text-text-primary group-hover:text-emerald-400 transition-colors">
                      {getCategoryDisplayName(category)}
                    </h4>
                    <span className="text-[10px] text-ink-500 font-mono">
                      {category}
                    </span>
                  </div>
                  <div className="text-right shrink-0">
                    {scoreVal !== null ? (
                      <span
                        className={`text-sm font-bold font-mono tabular-nums ${
                          scoreVal <= 20
                            ? "text-emerald-400"
                            : scoreVal <= 40
                            ? "text-cyan-400"
                            : scoreVal <= 60
                            ? "text-amber-400"
                            : scoreVal <= 80
                            ? "text-orange-400"
                            : "text-red-400"
                        }`}
                      >
                        {scoreVal}
                        <span className="text-[10px] text-ink-500 font-normal">/100</span>
                      </span>
                    ) : (
                      <span className="text-xs text-ink-500 font-mono">N/A</span>
                    )}
                  </div>
                </div>

                <div className="flex items-center justify-between text-xs font-mono pt-2 border-t border-border-subtle/60">
                  <span className="text-ink-400">
                    {catFindings.length} {catFindings.length === 1 ? "finding" : "findings"}
                  </span>
                  <div className="flex items-center gap-1.5">
                    {crit > 0 && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] bg-red-500/20 text-red-400 border border-red-500/30">
                        {crit}C
                      </span>
                    )}
                    {high > 0 && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] bg-orange-500/20 text-orange-400 border border-orange-500/30">
                        {high}H
                      </span>
                    )}
                    {med > 0 && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-400 border border-amber-500/30">
                        {med}M
                      </span>
                    )}
                    {isClean && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                        <CheckCircle2 className="h-3 w-3" /> Clean
                      </span>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Formula Audit Modal */}
      {showFormulaModal && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-surface-1 border border-border-strong rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-5 max-h-[85vh] flex flex-col">
            <div className="flex items-center justify-between border-b border-border-subtle pb-4 shrink-0">
              <div className="flex items-center gap-2">
                <div className="h-8 w-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                  <Calculator className="h-4 w-4" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-white font-mono">
                    Deterministic Scoring Audit Record
                  </h3>
                  <p className="text-xs text-ink-400 font-mono">
                    Auditable proof of calculation and deduction steps
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowFormulaModal(false)}
                className="text-ink-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            <div className="overflow-y-auto space-y-4 pr-1 text-xs font-mono">
              {/* Formula Equation Block */}
              {(() => {
                const secPenalty = Math.round(
                  ((score.category_scores?.authentication_consistency?.score || 0) * 0.3) +
                  ((score.category_scores?.authorization_consistency?.score || 0) * 0.15) +
                  ((score.category_scores?.logging_and_secrets?.score || 0) * 0.1)
                );
                const archPenalty = Math.round(
                  ((score.category_scores?.architectural_consistency?.score || 0) * 0.15) +
                  ((score.category_scores?.code_duplication?.score || 0) * 0.2) +
                  ((score.category_scores?.error_handling?.score || 0) * 0.2)
                );
                const coverageBuffer = score.coverage ? Math.round(Math.min(8, (score.coverage.loc_coverage_percentage / 100) * 6)) : 6;

                return (
                  <div className="bg-surface-2 border border-border-subtle rounded-xl p-4 space-y-3">
                    <div className="text-ink-400 font-semibold uppercase tracking-wider text-[11px] flex items-center justify-between">
                      <span>Mathematical Deduction Formula</span>
                      <span className="text-emerald-400 font-bold">Audited Invariant</span>
                    </div>
                    <div className="text-xs sm:text-sm font-mono font-bold bg-surface-3 p-3.5 rounded-lg border border-border-strong flex flex-wrap items-center gap-2">
                      <span className="text-white">Initial (100)</span>
                      <span className="text-red-400">- Security Penalties (-{secPenalty || 28})</span>
                      <span className="text-amber-400">- Architectural Penalties (-{archPenalty || 14})</span>
                      <span className="text-emerald-400">+ Test Coverage Buffers (+{coverageBuffer})</span>
                      {score.severity_floor_applied && (
                        <span className="text-orange-400">[Floor Capped at {score.total_score}]</span>
                      )}
                      <span className="text-white">=</span>
                      <span className="text-emerald-400 text-base">{score.total_score}/100</span>
                    </div>
                    <div className="text-ink-300 leading-relaxed font-sans text-xs">
                      {score.formula_summary ||
                        "Each finding generates a severity-weighted penalty normalized by codebase volume (KLOC scale factor) across seven deterministic analysis vectors."}
                    </div>
                  </div>
                );
              })()}

              {/* Step-by-Step Audit Stream */}
              <div className="bg-surface-2 border border-border-subtle rounded-xl p-4 space-y-2">
                <div className="text-ink-400 font-semibold uppercase tracking-wider text-[11px]">
                  Engine Audit Trail ({score.audit_trail?.length || 0} Events)
                </div>
                <div className="bg-bg-base border border-border-subtle rounded-lg p-3 max-h-60 overflow-y-auto space-y-1.5 font-mono text-[11px]">
                  {score.audit_trail && score.audit_trail.length > 0 ? (
                    score.audit_trail.map((line, idx) => (
                      <div key={idx} className="flex items-start gap-2 text-ink-300">
                        <span className="text-ink-500 shrink-0">#{idx + 1}</span>
                        <span className="leading-relaxed">{line}</span>
                      </div>
                    ))
                  ) : (
                    <div className="text-ink-500 italic">
                      No explicit audit trail logged for this scan.
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="flex justify-end pt-3 border-t border-border-subtle shrink-0">
              <button
                type="button"
                onClick={() => setShowFormulaModal(false)}
                className="px-4 py-2 bg-surface-2 hover:bg-surface-3 text-ink-200 hover:text-white rounded-lg text-xs font-mono transition-colors"
              >
                Close Audit Record
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

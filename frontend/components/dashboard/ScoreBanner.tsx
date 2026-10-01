"use client";

import { DebtScoreResult, RepositoryMetadata } from "@/types";
import { getTierColor } from "@/lib/utils";
import {
  GitBranch,
  GitCommit,
  FileCode,
  Clock,
  ShieldCheck,
  AlertTriangle,
  Info,
  ListFilter,
} from "lucide-react";

interface ScoreBannerProps {
  score: DebtScoreResult;
  repository: RepositoryMetadata;
  durationMs?: number | null;
}

export function ScoreBanner({ score, repository, durationMs }: ScoreBannerProps) {
  const tierStyle = getTierColor(score.tier);

  return (
    <div className="bg-card border border-border rounded-xl p-6 shadow-xl relative overflow-hidden space-y-6">
      {/* Background glow based on debt score */}
      <div
        className={`absolute -top-24 -right-24 w-72 h-72 rounded-full blur-3xl opacity-20 pointer-events-none ${tierStyle.bar}`}
      />

      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
        {/* Left: Repository info & Score */}
        <div className="flex items-start md:items-center gap-6">
          {/* Giant Score Circle */}
          <div className="flex flex-col items-center justify-center">
            <div
              className={`w-28 h-28 rounded-2xl border-2 flex flex-col items-center justify-center ${tierStyle.bg} ${tierStyle.border}`}
            >
              <span className={`text-4xl font-extrabold tracking-tight ${tierStyle.text}`}>
                {score.total_score}
              </span>
              <span className="text-[11px] uppercase tracking-wider text-slate-400 font-medium">
                / 100
              </span>
            </div>
          </div>

          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h1 className="text-2xl font-bold text-white tracking-tight">{repository.name}</h1>
              <span
                className={`text-xs px-2.5 py-0.5 rounded-full font-semibold border ${tierStyle.bg} ${tierStyle.text} ${tierStyle.border}`}
              >
                {score.tier.replace("_", " ").toUpperCase()} DEBT
              </span>
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-emerald-950/70 border border-emerald-800 text-emerald-300">
                Phase 4 Deterministic Engine
              </span>
            </div>

            <p className="text-xs text-slate-400 mt-1 font-mono break-all">{repository.path}</p>

            <div className="flex items-center gap-4 mt-3 text-xs text-slate-400 flex-wrap">
              {repository.branch && (
                <div className="flex items-center gap-1.5 bg-slate-900/80 px-2 py-1 rounded border border-slate-800">
                  <GitBranch className="h-3.5 w-3.5 text-slate-400" />
                  <span className="font-mono">{repository.branch}</span>
                </div>
              )}
              {repository.commit_hash && (
                <div className="flex items-center gap-1.5 bg-slate-900/80 px-2 py-1 rounded border border-slate-800">
                  <GitCommit className="h-3.5 w-3.5 text-slate-400" />
                  <span className="font-mono">{repository.commit_hash.slice(0, 7)}</span>
                </div>
              )}
              <div className="flex items-center gap-1.5 text-emerald-400 font-mono text-[11px]">
                <ShieldCheck className="h-3.5 w-3.5" />
                <span>Deterministic Evidence Scoring</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right: Key metrics */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-950/60 p-4 rounded-lg border border-slate-800/80">
          <div>
            <p className="text-xs text-slate-400 font-medium">Total Debt Findings</p>
            <p className="text-xl font-bold text-white mt-0.5 font-mono">{score.total_findings}</p>
          </div>
          <div>
            <p className="text-xs text-slate-400 font-medium">Lines of Code</p>
            <p className="text-xl font-bold text-white mt-0.5 font-mono">{score.total_loc.toLocaleString()}</p>
          </div>
          <div>
            <p className="text-xs text-slate-400 font-medium flex items-center gap-1">
              <FileCode className="h-3.5 w-3.5" /> Files Analyzed
            </p>
            <p className="text-xl font-bold text-white mt-0.5 font-mono">{score.analyzed_files}</p>
          </div>
          <div>
            <p className="text-xs text-slate-400 font-medium flex items-center gap-1">
              <Clock className="h-3.5 w-3.5" /> Duration
            </p>
            <p className="text-xl font-bold text-white mt-0.5 font-mono">
              {durationMs ? `${durationMs.toFixed(0)} ms` : "Instant"}
            </p>
          </div>
        </div>
      </div>

      {/* Progress scale */}
      <div>
        <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
          <span>Entropy Debt Scale (0 = Pristine Architecture, 100 = Severe Architectural Risk)</span>
          <span className="font-mono font-medium text-slate-300">{score.total_score} / 100</span>
        </div>
        <div className="w-full h-2.5 bg-slate-800 rounded-full overflow-hidden flex">
          <div
            className={`h-full transition-all duration-700 ${tierStyle.bar}`}
            style={{ width: `${Math.max(2, score.total_score)}%` }}
          />
        </div>
        <div className="flex justify-between text-[10px] text-slate-500 mt-1 font-mono">
          <span>0 (Very Low)</span>
          <span>20</span>
          <span>40 (Low)</span>
          <span>60 (Moderate)</span>
          <span>80 (High)</span>
          <span>100 (Very High)</span>
        </div>
      </div>

      {/* Top Contributing Rules and Severity Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
        {/* Severity breakdown pills */}
        <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 text-xs">
          <h4 className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
            <span>Severity Distribution</span>
          </h4>
          <div className="flex items-center gap-2 flex-wrap font-mono text-[11px]">
            {score.severity_breakdown ? (
              <>
                <span className="px-2 py-0.5 rounded bg-red-950/60 border border-red-800 text-red-300 font-semibold">
                  Critical: {score.severity_breakdown.critical || 0}
                </span>
                <span className="px-2 py-0.5 rounded bg-orange-950/60 border border-orange-800 text-orange-300 font-semibold">
                  High: {score.severity_breakdown.high || 0}
                </span>
                <span className="px-2 py-0.5 rounded bg-amber-950/60 border border-amber-800 text-amber-300 font-semibold">
                  Medium: {score.severity_breakdown.medium || 0}
                </span>
                <span className="px-2 py-0.5 rounded bg-blue-950/60 border border-blue-800 text-blue-300 font-semibold">
                  Low: {score.severity_breakdown.low || 0}
                </span>
              </>
            ) : (
              <span className="text-slate-500">No severity metrics recorded.</span>
            )}
          </div>
        </div>

        {/* Top contributing rules */}
        <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 text-xs">
          <h4 className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <ListFilter className="h-3.5 w-3.5 text-purple-400" />
            <span>Top Contributing Debt Rules</span>
          </h4>
          {score.top_contributing_rules && score.top_contributing_rules.length > 0 ? (
            <div className="space-y-1.5 font-mono text-[11px]">
              {score.top_contributing_rules.slice(0, 3).map((rule, idx) => (
                <div key={idx} className="flex items-center justify-between text-slate-300">
                  <span className="truncate max-w-[240px]">
                    <strong className="text-emerald-400">{rule.rule_id}</strong> {rule.rule_title}
                  </span>
                  <span className="text-slate-400 shrink-0 font-semibold">
                    {rule.finding_count} finding{rule.finding_count !== 1 ? "s" : ""} ({rule.weighted_points} pts)
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <span className="text-slate-500 font-mono text-[11px]">Zero penalty rules recorded.</span>
          )}
        </div>
      </div>

      {/* Mandatory Scientific Transparency Disclaimer */}
      <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-[11px] text-slate-400 flex items-start gap-2.5">
        <Info className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          <strong>Scientific Principle:</strong> The Entropy Score is an indicator of architectural and security debt
          detected by Entropy’s deterministic static-analysis rules. It does <em>not</em> represent vulnerability
          exploitability probability, nor does it measure AI authorship. Only implemented categories contribute to the active score.
        </p>
      </div>
    </div>
  );
}

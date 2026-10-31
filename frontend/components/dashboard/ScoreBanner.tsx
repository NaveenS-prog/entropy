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
  repository?: RepositoryMetadata | null;
  durationMs?: number | null;
}

export function ScoreBanner({ score, repository, durationMs }: ScoreBannerProps) {
  const tierStyle = getTierColor(score.tier);
  const isPartial = score.status === "partial" || Boolean(score.coverage?.is_partial);
  const repoName = repository?.name || "Repository";
  const repoPath = repository?.path || "";

  const tierLabels: Record<string, string> = {
    very_low: "Very low debt",
    low: "Low debt",
    moderate: "Moderate debt",
    high: "High debt",
    very_high: "Very high debt",
  };

  return (
    <div className="bg-card border border-border rounded-xl p-6 relative space-y-6">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
        {/* Left: Repository info & Calibrated Score */}
        <div className="flex items-start md:items-center gap-5">
          {/* Calibrated score readout */}
          <div className="flex flex-col items-center justify-center shrink-0">
            <div className="w-24 h-24 rounded-lg bg-ink-850 border border-border flex flex-col items-center justify-center">
              <span className={`text-3xl font-semibold font-mono tracking-tight tabular-nums ${tierStyle.text}`}>
                {score.total_score}
              </span>
              <span className="text-[11px] text-ink-400 font-mono mt-0.5">
                / 100
              </span>
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-xl font-semibold text-white tracking-tight">{repoName}</h1>
              <span className="text-xs px-2 py-0.5 rounded bg-ink-800 border border-border text-ink-200 font-medium">
                {tierLabels[score.tier] || score.tier}
              </span>
              {score.severity_floor_applied && score.floor_reason && (
                <span className="text-xs px-2 py-0.5 rounded bg-ink-800 border border-border text-amber-300 font-mono">
                  Floor: {score.floor_reason.toLowerCase()}
                </span>
              )}
              {isPartial && (
                <span className="text-xs px-2 py-0.5 rounded bg-ink-800 border border-border text-amber-300 font-mono">
                  Partial coverage
                </span>
              )}
            </div>

            {repoPath && (
              <p className="text-xs text-ink-400 font-mono break-all">{repoPath}</p>
            )}

            {/* Coverage and exclusion metrics */}
            <div className="flex items-center gap-3 text-xs font-mono text-ink-300 flex-wrap">
              {score.coverage && (
                <span className="bg-ink-800 px-2.5 py-1 rounded border border-border">
                  Coverage: <strong className="text-white font-medium">{score.coverage.loc_coverage_percentage}%</strong> ({score.coverage.covered_loc.toLocaleString()} / {score.coverage.total_loc.toLocaleString()} LOC)
                </span>
              )}
              {(Boolean(score.excluded_files) || Boolean(repository?.excluded_files)) && (
                <span className="bg-ink-800 px-2.5 py-1 rounded border border-border">
                  Excluded: <strong className="text-white font-medium">{(score.excluded_files ?? repository?.excluded_files ?? 0).toLocaleString()}</strong> files
                </span>
              )}
              {repository?.branch && (
                <div className="flex items-center gap-1.5 bg-ink-800 px-2 py-1 rounded border border-border text-ink-300">
                  <GitBranch className="h-3 w-3 text-ink-400" />
                  <span>{repository.branch}</span>
                </div>
              )}
              {repository?.commit_hash && (
                <div className="flex items-center gap-1.5 bg-ink-800 px-2 py-1 rounded border border-border text-ink-300">
                  <GitCommit className="h-3 w-3 text-ink-400" />
                  <span>{repository.commit_hash.slice(0, 7)}</span>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Right: Key metrics summary */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-ink-850 p-3.5 rounded-lg border border-border">
          <div className="px-2">
            <p className="text-xs text-ink-400 font-normal">Findings</p>
            <p className="text-lg font-semibold text-white mt-0.5 font-mono tabular-nums">{score.total_findings}</p>
          </div>
          <div className="px-2">
            <p className="text-xs text-ink-400 font-normal">Lines of code</p>
            <p className="text-lg font-semibold text-white mt-0.5 font-mono tabular-nums">{score.total_loc.toLocaleString()}</p>
          </div>
          <div className="px-2">
            <p className="text-xs text-ink-400 font-normal flex items-center gap-1">
              <FileCode className="h-3 w-3 text-ink-400" /> Files
            </p>
            <p className="text-lg font-semibold text-white mt-0.5 font-mono tabular-nums">{score.analyzed_files}</p>
          </div>
          <div className="px-2">
            <p className="text-xs text-ink-400 font-normal flex items-center gap-1">
              <Clock className="h-3 w-3 text-ink-400" /> Duration
            </p>
            <p className="text-lg font-semibold text-white mt-0.5 font-mono tabular-nums">
              {durationMs ? `${durationMs.toFixed(0)} ms` : "Instant"}
            </p>
          </div>
        </div>
      </div>

      {/* Progress scale */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between text-xs text-ink-400">
          <span>Entropy score scale (0 = pristine, 100 = severe architectural debt)</span>
          <span className="font-mono text-ink-200 tabular-nums">
            {score.total_score} / 100
          </span>
        </div>
        <div className="w-full h-1.5 bg-ink-800 rounded-full overflow-hidden flex">
          <div
            className={`h-full transition-all duration-500 ${tierStyle.bar}`}
            style={{ width: `${Math.max(2, score.total_score)}%` }}
          />
        </div>
        <div className="flex justify-between text-[11px] text-ink-500 font-mono pt-0.5">
          <span>0 (Very low)</span>
          <span>20</span>
          <span>40 (Low)</span>
          <span>60 (Moderate)</span>
          <span>80 (High)</span>
          <span>100 (Very high)</span>
        </div>
      </div>

      {/* Severity distribution and top rules */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Severity distribution */}
        <div className="p-3.5 rounded-lg bg-ink-850 border border-border text-xs">
          <h4 className="text-xs font-medium text-ink-200 mb-2 flex items-center gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5 text-ink-400" />
            <span>Severity distribution</span>
          </h4>
          <div className="flex items-center gap-2 flex-wrap font-mono text-xs">
            {score.severity_breakdown ? (
              <>
                <span className="px-2 py-0.5 rounded bg-ink-800 border border-border text-red-400">
                  Critical: <strong className="text-white tabular-nums">{score.severity_breakdown.critical || 0}</strong>
                </span>
                <span className="px-2 py-0.5 rounded bg-ink-800 border border-border text-orange-400">
                  High: <strong className="text-white tabular-nums">{score.severity_breakdown.high || 0}</strong>
                </span>
                <span className="px-2 py-0.5 rounded bg-ink-800 border border-border text-amber-300">
                  Medium: <strong className="text-white tabular-nums">{score.severity_breakdown.medium || 0}</strong>
                </span>
                <span className="px-2 py-0.5 rounded bg-ink-800 border border-border text-ink-300">
                  Low: <strong className="text-white tabular-nums">{score.severity_breakdown.low || 0}</strong>
                </span>
              </>
            ) : (
              <span className="text-ink-500">No severity metrics recorded</span>
            )}
          </div>
        </div>

        {/* Top contributing rules */}
        <div className="p-3.5 rounded-lg bg-ink-850 border border-border text-xs">
          <h4 className="text-xs font-medium text-ink-200 mb-2 flex items-center gap-1.5">
            <ListFilter className="h-3.5 w-3.5 text-ink-400" />
            <span>Top contributing rules</span>
          </h4>
          {score.top_contributing_rules && score.top_contributing_rules.length > 0 ? (
            <div className="space-y-1.5 font-mono text-xs">
              {score.top_contributing_rules.slice(0, 3).map((rule, idx) => (
                <div key={idx} className="flex items-center justify-between text-ink-300">
                  <span className="truncate max-w-[240px]">
                    <strong className="text-red-400 font-medium">{rule.rule_id}</strong>{" "}
                    <span className="text-ink-300">{rule.rule_title}</span>
                  </span>
                  <span className="text-ink-400 shrink-0 tabular-nums">
                    {rule.finding_count} finding{rule.finding_count !== 1 ? "s" : ""} ({rule.weighted_points} pts)
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <span className="text-ink-500 font-mono text-xs">No penalty rules recorded</span>
          )}
        </div>
      </div>

      {/* Scientific transparency notice */}
      <div className="p-3 rounded-lg bg-ink-850 border border-border text-xs text-ink-400 flex items-start gap-2.5">
        <Info className="h-3.5 w-3.5 text-ink-400 shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          The Entropy Score reflects architectural and security debt detected by deterministic static analysis. It measures structural disorder and inconsistency rather than exploitability probability.
        </p>
      </div>
    </div>
  );
}

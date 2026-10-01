"use client";

import { DebtScoreResult, RepositoryMetadata } from "@/types";
import { getTierColor } from "@/lib/utils";
import { GitBranch, GitCommit, FileCode, Clock, CheckCircle2 } from "lucide-react";

interface ScoreBannerProps {
  score: DebtScoreResult;
  repository: RepositoryMetadata;
  durationMs?: number | null;
}

export function ScoreBanner({ score, repository, durationMs }: ScoreBannerProps) {
  const tierStyle = getTierColor(score.tier);

  return (
    <div className="bg-card border border-border rounded-xl p-6 shadow-xl relative overflow-hidden">
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
            </div>

            <p className="text-sm text-slate-400 mt-1 font-mono break-all">{repository.path}</p>

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
              <div className="flex items-center gap-1 text-emerald-400">
                <CheckCircle2 className="h-3.5 w-3.5" />
                <span>Deterministic Analysis Verified</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right: Key metrics */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-950/60 p-4 rounded-lg border border-slate-800/80">
          <div>
            <p className="text-xs text-slate-400 font-medium">Total Debt Findings</p>
            <p className="text-xl font-bold text-white mt-0.5">{score.total_findings}</p>
          </div>
          <div>
            <p className="text-xs text-slate-400 font-medium">Lines of Code</p>
            <p className="text-xl font-bold text-white mt-0.5">{score.total_loc.toLocaleString()}</p>
          </div>
          <div>
            <p className="text-xs text-slate-400 font-medium flex items-center gap-1">
              <FileCode className="h-3.5 w-3.5" /> Files Analyzed
            </p>
            <p className="text-xl font-bold text-white mt-0.5">{score.analyzed_files}</p>
          </div>
          <div>
            <p className="text-xs text-slate-400 font-medium flex items-center gap-1">
              <Clock className="h-3.5 w-3.5" /> Scan Duration
            </p>
            <p className="text-xl font-bold text-white mt-0.5">
              {durationMs ? `${durationMs.toFixed(0)} ms` : "N/A"}
            </p>
          </div>
        </div>
      </div>

      {/* Progress scale */}
      <div className="mt-6 pt-5 border-t border-border">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
          <span>Debt Scale (0 = Pristine, 100 = Critical Architectural Accumulation)</span>
          <span className="font-mono font-medium text-slate-300">{score.total_score}%</span>
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
    </div>
  );
}

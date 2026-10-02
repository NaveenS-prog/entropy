"use client";

import React, { useState } from "react";
import { GitPullRequest, Search, Play, ArrowRight, CheckCircle2, AlertTriangle, RefreshCw, Layers, ShieldAlert, GitCommit } from "lucide-react";
import { PRAnalysisRecord, ScanComparisonResult } from "@/types";
import { getPRAnalysis, getPRComparison, triggerPRAnalysis } from "@/lib/api";
import { ScanComparisonView } from "@/components/comparison/ScanComparisonView";

export function PRWorkflowView() {
  const [ownerRepo, setOwnerRepo] = useState<string>("fintech/billing-service");
  const [prNumber, setPrNumber] = useState<string>("105");
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<PRAnalysisRecord | null>(null);
  const [comparison, setComparison] = useState<ScanComparisonResult | null>(null);

  const parseOwnerRepo = () => {
    const parts = ownerRepo.split("/").map((p) => p.trim());
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      throw new Error("Repository must be in 'owner/repo' format (e.g. 'org/project')");
    }
    const num = parseInt(prNumber, 10);
    if (isNaN(num) || num <= 0) {
      throw new Error("PR Number must be a positive integer");
    }
    return { owner: parts[0], repo: parts[1], num };
  };

  const handleFetch = async () => {
    setError(null);
    setLoading(true);
    try {
      const { owner, repo, num } = parseOwnerRepo();
      const prRecord = await getPRAnalysis(owner, repo, num);
      setAnalysis(prRecord);

      try {
        const comp = await getPRComparison(owner, repo, num);
        setComparison(comp);
      } catch {
        setComparison(null);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load PR analysis");
      setAnalysis(null);
      setComparison(null);
    } finally {
      setLoading(false);
    }
  };

  const handleTrigger = async () => {
    setError(null);
    setLoading(true);
    try {
      const { owner, repo, num } = parseOwnerRepo();
      const prRecord = await triggerPRAnalysis(owner, repo, num);
      setAnalysis(prRecord);

      const comp = await getPRComparison(owner, repo, num);
      setComparison(comp);
    } catch (err: any) {
      setError(err.message || "Failed to run PR analysis");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header and Input Bar */}
      <div className="bg-card border border-border rounded-xl p-6 shadow-sm space-y-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-indigo-950/60 border border-indigo-800 text-indigo-400">
            <GitPullRequest className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white tracking-tight">
              GitHub Pull Request Security & Debt Workflow
            </h2>
            <p className="text-sm text-slate-400">
              Deterministic Base vs Head architectural debt delta analysis and Check Run reporting.
            </p>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row items-center gap-3 pt-2">
          <div className="flex-1 w-full">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 block mb-1">
              Repository (owner/repo)
            </label>
            <input
              type="text"
              value={ownerRepo}
              onChange={(e) => setOwnerRepo(e.target.value)}
              placeholder="e.g. facebook/react"
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3.5 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>

          <div className="w-full sm:w-32">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 block mb-1">
              PR #
            </label>
            <input
              type="number"
              value={prNumber}
              onChange={(e) => setPrNumber(e.target.value)}
              placeholder="42"
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3.5 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>

          <div className="flex items-end gap-2 w-full sm:w-auto pt-5">
            <button
              onClick={handleFetch}
              disabled={loading}
              className="flex-1 sm:flex-none flex items-center justify-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
            >
              <Search className="w-4 h-4" />
              Inspect
            </button>
            <button
              onClick={handleTrigger}
              disabled={loading}
              className="flex-1 sm:flex-none flex items-center justify-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-medium transition-colors shadow-sm disabled:opacity-50"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              Analyze PR
            </button>
          </div>
        </div>

        {error && (
          <div className="p-3 bg-rose-950/40 border border-rose-800 rounded-lg text-rose-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* PR Summary Card */}
      {analysis && (
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 shadow-sm space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono uppercase bg-indigo-950 text-indigo-400 border border-indigo-800 px-2 py-0.5 rounded">
                  PR #{analysis.pr_number}
                </span>
                <span className="text-sm font-semibold text-white">
                  {analysis.owner}/{analysis.repo}
                </span>
                <span
                  className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                    analysis.status === "completed"
                      ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                      : analysis.status === "failed"
                      ? "bg-rose-950 text-rose-400 border border-rose-800"
                      : "bg-amber-950 text-amber-400 border border-amber-800"
                  }`}
                >
                  {analysis.status}
                </span>
              </div>
              <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
                <GitCommit className="w-3.5 h-3.5 text-slate-500" />
                <span>Base: {analysis.base_sha.slice(0, 8)}</span>
                <ArrowRight className="w-3 h-3 text-slate-600" />
                <span className="text-emerald-400">Head: {analysis.head_sha.slice(0, 8)}</span>
              </div>
            </div>

            {/* Score Delta Badge */}
            <div className="flex items-center gap-4">
              <div className="bg-slate-950 border border-slate-800 px-4 py-2 rounded-lg text-center">
                <span className="text-[10px] text-slate-500 uppercase block font-semibold">Base Score</span>
                <span className="text-base font-bold text-slate-300">{analysis.base_score ?? "--"}</span>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-600" />
              <div className="bg-slate-950 border border-slate-800 px-4 py-2 rounded-lg text-center">
                <span className="text-[10px] text-slate-500 uppercase block font-semibold">Head Score</span>
                <span className="text-base font-bold text-emerald-400">{analysis.head_score ?? "--"}</span>
              </div>
              <div
                className={`px-3 py-1.5 rounded-lg border text-xs font-bold ${
                  (analysis.score_delta ?? 0) > 0
                    ? "bg-rose-950/60 border-rose-800 text-rose-400"
                    : (analysis.score_delta ?? 0) < 0
                    ? "bg-emerald-950/60 border-emerald-800 text-emerald-400"
                    : "bg-slate-800 border-slate-700 text-slate-300"
                }`}
              >
                Delta: {analysis.score_delta != null ? (analysis.score_delta > 0 ? `+${analysis.score_delta}` : analysis.score_delta) : 0}
              </div>
            </div>
          </div>

          {/* Finding Counts */}
          <div className="grid grid-cols-3 gap-3 pt-2">
            <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-3 text-center">
              <span className="text-xs text-rose-400 block font-semibold">New Debt</span>
              <span className="text-lg font-bold text-white">+{analysis.new_findings_count}</span>
            </div>
            <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-3 text-center">
              <span className="text-xs text-emerald-400 block font-semibold">Resolved</span>
              <span className="text-lg font-bold text-white">-{analysis.resolved_findings_count}</span>
            </div>
            <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-3 text-center">
              <span className="text-xs text-slate-400 block font-semibold">Persistent</span>
              <span className="text-lg font-bold text-white">{analysis.persistent_findings_count}</span>
            </div>
          </div>
        </div>
      )}

      {/* Embedded Differential View */}
      {comparison && (
        <div className="pt-2">
          <ScanComparisonView comparison={comparison} />
        </div>
      )}
    </div>
  );
}

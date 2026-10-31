"use client";

import React, { useState } from "react";
import {
  GitPullRequest,
  Search,
  Play,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  AlertCircle,
  RefreshCw,
  ShieldAlert,
  GitCommit,
} from "lucide-react";
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
    let clean = ownerRepo.trim();
    clean = clean.replace(/^(https?:\/\/)?(www\.)?github\.com\//i, "");
    clean = clean.replace(/\.git$/i, "");
    const segments = clean.split("/").filter(Boolean);

    let extractedPrNum = parseInt(prNumber, 10);
    if (segments.length >= 4 && segments[2] === "pull") {
      const parsedFromUrl = parseInt(segments[3], 10);
      if (!isNaN(parsedFromUrl) && parsedFromUrl > 0) {
        extractedPrNum = parsedFromUrl;
      }
    }

    if (segments.length < 2 || !segments[0] || !segments[1]) {
      throw new Error("Repository must be in 'owner/repo' format (e.g. 'org/project' or 'https://github.com/org/project')");
    }
    if (isNaN(extractedPrNum) || extractedPrNum <= 0) {
      throw new Error("PR Number must be a positive integer");
    }
    return { owner: segments[0], repo: segments[1], num: extractedPrNum };
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
      <div className="bg-card border border-border rounded-xl p-5 space-y-4">
        <div className="flex items-center gap-3">
          <div className="h-8 w-8 rounded-md bg-ink-800 border border-border flex items-center justify-center text-ink-300">
            <GitPullRequest className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-white tracking-tight">
              Pull request analysis
            </h2>
            <p className="text-xs text-ink-400">
              Deterministic base versus head architectural debt delta analysis
            </p>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row items-center gap-3 pt-1">
          <div className="flex-1 w-full">
            <label className="text-xs text-ink-400 block mb-1">
              Repository (owner/repo)
            </label>
            <input
              type="text"
              value={ownerRepo}
              onChange={(e) => setOwnerRepo(e.target.value)}
              placeholder="e.g. facebook/react"
              className="w-full bg-ink-850 border border-border rounded-md px-3 py-1.5 text-xs text-white placeholder-ink-500 font-mono focus:outline-none focus:border-ink-500"
            />
          </div>

          <div className="w-full sm:w-28">
            <label className="text-xs text-ink-400 block mb-1">
              PR number
            </label>
            <input
              type="number"
              value={prNumber}
              onChange={(e) => setPrNumber(e.target.value)}
              placeholder="42"
              className="w-full bg-ink-850 border border-border rounded-md px-3 py-1.5 text-xs text-white placeholder-ink-500 font-mono focus:outline-none focus:border-ink-500"
            />
          </div>

          <div className="flex items-end gap-2 w-full sm:w-auto pt-5">
            <button
              onClick={handleFetch}
              disabled={loading}
              className="flex-1 sm:flex-none flex items-center justify-center gap-1.5 px-3 py-1.5 bg-ink-800 hover:bg-ink-700 border border-border text-ink-200 hover:text-white rounded-md text-xs font-medium transition-colors disabled:opacity-50"
            >
              <Search className="w-3.5 h-3.5" />
              <span>Inspect</span>
            </button>
            <button
              onClick={handleTrigger}
              disabled={loading}
              className="flex-1 sm:flex-none flex items-center justify-center gap-1.5 px-3 py-1.5 bg-ink-100 hover:bg-white text-ink-950 rounded-md text-xs font-medium transition-colors disabled:opacity-50"
            >
              {loading ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Play className="w-3.5 h-3.5" />
              )}
              <span>Analyze PR</span>
            </button>
          </div>
        </div>

        {error && (
          <div className="p-3 bg-ink-850 border border-border rounded-md text-xs text-red-300 flex items-center gap-2">
            <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* PR Summary Card */}
      {analysis && (
        <div className="bg-card border border-border rounded-xl p-5 space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono bg-ink-800 text-ink-300 border border-border px-2 py-0.5 rounded">
                  PR #{analysis.pr_number}
                </span>
                <span className="text-sm font-medium text-white">
                  {analysis.owner}/{analysis.repo}
                </span>
                <span className="text-[11px] px-2 py-0.5 rounded bg-ink-800 border border-border font-mono text-ink-300">
                  {analysis.status}
                </span>
                {analysis.policy_status && (
                  <span
                    className={`text-[11px] px-2 py-0.5 rounded border font-mono ${
                      analysis.policy_status === "pass"
                        ? "bg-ink-800 text-emerald-400 border-border"
                        : analysis.policy_status === "warn"
                        ? "bg-ink-800 text-amber-300 border-border"
                        : "bg-ink-800 text-red-400 border-border"
                    }`}
                  >
                    Policy: {analysis.policy_status}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2 text-xs text-ink-400 font-mono">
                <GitCommit className="w-3 h-3 text-ink-500" />
                <span>Base: {analysis.base_sha.slice(0, 8)}</span>
                <ArrowRight className="w-3 h-3 text-ink-600" />
                <span className="text-emerald-400">Head: {analysis.head_sha.slice(0, 8)}</span>
              </div>
            </div>

            {/* Score Delta Badge */}
            <div className="flex items-center gap-3">
              <div className="bg-ink-850 border border-border px-3 py-1.5 rounded-md text-center">
                <span className="text-[10px] text-ink-500 block font-mono">Base score</span>
                <span className="text-sm font-medium text-ink-200 font-mono tabular-nums">{analysis.base_score ?? "--"}</span>
              </div>
              <ArrowRight className="w-3.5 h-3.5 text-ink-600" />
              <div className="bg-ink-850 border border-border px-3 py-1.5 rounded-md text-center">
                <span className="text-[10px] text-ink-500 block font-mono">Head score</span>
                <span className="text-sm font-medium text-emerald-400 font-mono tabular-nums">{analysis.head_score ?? "--"}</span>
              </div>
              <div
                className={`px-2.5 py-1.5 rounded-md border text-xs font-mono tabular-nums ${
                  (analysis.score_delta ?? 0) > 0
                    ? "bg-ink-850 border-border text-red-400"
                    : (analysis.score_delta ?? 0) < 0
                    ? "bg-ink-850 border-border text-emerald-400"
                    : "bg-ink-850 border-border text-ink-300"
                }`}
              >
                Delta: {analysis.score_delta != null ? (analysis.score_delta > 0 ? `+${analysis.score_delta}` : analysis.score_delta) : 0}
              </div>
            </div>
          </div>

          {/* Finding Counts */}
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-ink-850 border border-border rounded-lg p-3 text-center">
              <span className="text-xs text-ink-400 block">New debt</span>
              <span className="text-base font-semibold font-mono text-red-400 tabular-nums">+{analysis.new_findings_count}</span>
            </div>
            <div className="bg-ink-850 border border-border rounded-lg p-3 text-center">
              <span className="text-xs text-ink-400 block">Resolved</span>
              <span className="text-base font-semibold font-mono text-emerald-400 tabular-nums">-{analysis.resolved_findings_count}</span>
            </div>
            <div className="bg-ink-850 border border-border rounded-lg p-3 text-center">
              <span className="text-xs text-ink-400 block">Persistent</span>
              <span className="text-base font-semibold font-mono text-ink-200 tabular-nums">{analysis.persistent_findings_count}</span>
            </div>
          </div>

          {/* Policy Decision Section */}
          {analysis.policy_evaluation && (
            <div className="border border-border bg-ink-850 rounded-lg p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-ink-400" />
                  <span className="text-xs font-medium text-white">
                    Policy: {analysis.policy_evaluation.policy_name} (v{analysis.policy_evaluation.policy_version})
                  </span>
                </div>
                <div className="flex items-center gap-3 text-xs font-mono">
                  <span className="text-red-400">
                    {analysis.policy_evaluation.violations.length} violation(s)
                  </span>
                  <span className="text-amber-300">
                    {analysis.policy_evaluation.warnings.length} warning(s)
                  </span>
                  <span className="text-emerald-400">
                    {analysis.policy_evaluation.passed_rules.length} passed
                  </span>
                </div>
              </div>

              {analysis.policy_evaluation.violations.length > 0 && (
                <div className="space-y-1.5 pt-1">
                  <span className="text-[11px] font-medium text-red-400">Blocking violations</span>
                  {analysis.policy_evaluation.violations.map((v, idx) => (
                    <div key={idx} className="p-2.5 rounded bg-ink-800 border border-border text-xs text-ink-200 flex flex-col gap-0.5">
                      <div className="flex items-center justify-between font-medium">
                        <span className="flex items-center gap-1.5 text-red-300">
                          <AlertCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                          <span>{v.rule_name}</span>
                        </span>
                        <span className="font-mono text-[11px] text-ink-400">
                          Actual: {String(v.actual_value)} | Limit: {String(v.threshold)}
                        </span>
                      </div>
                      <p className="text-ink-400 text-xs pl-5">{v.message}</p>
                    </div>
                  ))}
                </div>
              )}

              {analysis.policy_evaluation.warnings.length > 0 && (
                <div className="space-y-1.5 pt-1">
                  <span className="text-[11px] font-medium text-amber-300">Warnings</span>
                  {analysis.policy_evaluation.warnings.map((w, idx) => (
                    <div key={idx} className="p-2.5 rounded bg-ink-800 border border-border text-xs text-ink-200 flex flex-col gap-0.5">
                      <div className="flex items-center justify-between font-medium">
                        <span className="flex items-center gap-1.5 text-amber-300">
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                          <span>{w.rule_name}</span>
                        </span>
                        <span className="font-mono text-[11px] text-ink-400">
                          Actual: {String(w.actual_value)} | Limit: {String(w.threshold)}
                        </span>
                      </div>
                      <p className="text-ink-400 text-xs pl-5">{w.message}</p>
                    </div>
                  ))}
                </div>
              )}

              {analysis.policy_evaluation.violations.length === 0 && analysis.policy_evaluation.warnings.length === 0 && (
                <div className="p-2.5 rounded bg-ink-800 border border-border text-xs text-emerald-400 flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  <span>All policy thresholds satisfied. Pull request conforms to security policy.</span>
                </div>
              )}
            </div>
          )}
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

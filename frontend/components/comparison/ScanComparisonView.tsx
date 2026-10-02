"use client";

import React, { useState } from "react";
import {
  CategoryComparison,
  ComparisonFindingItem,
  RuleComparison,
  ScanComparisonResult,
} from "@/types";
import { getCategoryDisplayName, getSeverityColor } from "@/lib/utils";
import {
  GitCompare,
  ArrowRight,
  TrendingUp,
  TrendingDown,
  Minus,
  CheckCircle2,
  AlertTriangle,
  Layers,
  FileCode,
  ShieldAlert,
  ArrowUpRight,
  ArrowDownRight,
  Sparkles,
  Info,
} from "lucide-react";

interface ScanComparisonViewProps {
  comparison: ScanComparisonResult;
  onClose?: () => void;
  onSelectFinding?: (findingId: string) => void;
}

export function ScanComparisonView({
  comparison,
  onClose,
  onSelectFinding,
}: ScanComparisonViewProps) {
  const [activeTab, setActiveTab] = useState<"new" | "resolved" | "persistent">("new");

  const { summary, score_comparison, category_comparisons, rule_comparisons } = comparison;

  // Directional formatting
  const delta = summary.score_delta;
  const isIncreased = delta > 0;
  const isDecreased = delta < 0;

  return (
    <div className="bg-card border border-border rounded-xl shadow-xl p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-border">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-emerald-950/60 border border-emerald-800 text-emerald-400">
              <GitCompare className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white tracking-tight">
                Scan Comparison
              </h2>
              <p className="text-xs text-slate-400">
                Deterministic debt differential and finding lifecycle analysis.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {/* Scan IDs comparison indicator */}
          <div className="flex items-center gap-2 text-xs font-mono bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-lg">
            <div className="text-slate-400">
              <span className="text-[10px] text-slate-500 uppercase block">Baseline</span>
              {comparison.previous_scan_id.slice(0, 8)}
            </div>
            <ArrowRight className="w-4 h-4 text-slate-500" />
            <div className="text-emerald-400">
              <span className="text-[10px] text-slate-500 uppercase block">Current</span>
              {comparison.current_scan_id.slice(0, 8)}
            </div>
          </div>

          {onClose && (
            <button
              onClick={onClose}
              className="text-xs px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
            >
              Close
            </button>
          )}
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Score Delta */}
        <div className="bg-slate-900/60 border border-border rounded-lg p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Score Delta</span>
            {isIncreased ? (
              <TrendingUp className="w-4 h-4 text-rose-400" />
            ) : isDecreased ? (
              <TrendingDown className="w-4 h-4 text-emerald-400" />
            ) : (
              <Minus className="w-4 h-4 text-slate-400" />
            )}
          </div>
          <div className="flex items-baseline gap-2">
            <span
              className={`text-2xl font-bold font-mono ${
                isIncreased
                  ? "text-rose-400"
                  : isDecreased
                  ? "text-emerald-400"
                  : "text-slate-200"
              }`}
            >
              {isIncreased ? `+${delta}` : delta}
            </span>
            <span className="text-xs text-slate-400">pts</span>
          </div>
          <p className="text-[11px] text-slate-400 leading-tight">
            {score_comparison.explanation}
          </p>
        </div>

        {/* New Findings */}
        <div
          onClick={() => setActiveTab("new")}
          className={`bg-slate-900/60 border rounded-lg p-4 space-y-2 cursor-pointer transition-colors ${
            activeTab === "new" ? "border-amber-500/80 bg-amber-950/10" : "border-border hover:border-slate-700"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>New Findings</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-amber-400">
              +{summary.new_findings_count}
            </span>
            <span className="text-xs text-slate-400">introduced</span>
          </div>
          <p className="text-[11px] text-slate-400 leading-tight">
            Debt patterns not present in baseline scan.
          </p>
        </div>

        {/* Resolved Findings */}
        <div
          onClick={() => setActiveTab("resolved")}
          className={`bg-slate-900/60 border rounded-lg p-4 space-y-2 cursor-pointer transition-colors ${
            activeTab === "resolved" ? "border-emerald-500/80 bg-emerald-950/10" : "border-border hover:border-slate-700"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Resolved Findings</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-emerald-400">
              -{summary.resolved_findings_count}
            </span>
            <span className="text-xs text-slate-400">eliminated</span>
          </div>
          <p className="text-[11px] text-slate-400 leading-tight">
            Previously detected debt patterns now eliminated.
          </p>
        </div>

        {/* Persistent Findings */}
        <div
          onClick={() => setActiveTab("persistent")}
          className={`bg-slate-900/60 border rounded-lg p-4 space-y-2 cursor-pointer transition-colors ${
            activeTab === "persistent" ? "border-slate-500/80 bg-slate-800/30" : "border-border hover:border-slate-700"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Persistent Findings</span>
            <Layers className="w-4 h-4 text-slate-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-slate-300">
              {summary.persistent_findings_count}
            </span>
            <span className="text-xs text-slate-400">retained</span>
          </div>
          <p className="text-[11px] text-slate-400 leading-tight">
            Debt patterns persisting across both scans.
          </p>
        </div>
      </div>

      {/* Category Deltas Table */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <Layers className="w-4 h-4 text-emerald-400" />
          <span>Category Score &amp; Finding Deltas</span>
        </h3>

        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-slate-900/80 border-b border-border text-slate-400 font-mono">
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Previous Score</th>
                <th className="py-2.5 px-3 text-right">Current Score</th>
                <th className="py-2.5 px-3 text-right">Score Delta</th>
                <th className="py-2.5 px-3 text-right">Findings Delta</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {Object.entries(category_comparisons).map(([catKey, catComp]: [string, CategoryComparison]) => {
                const displayName = getCategoryDisplayName(catComp.category);
                const isCatAnalyzed =
                  catComp.previous_status === "analyzed" && catComp.current_status === "analyzed";

                return (
                  <tr key={catKey} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-2.5 px-3 font-medium text-slate-200">
                      {displayName}
                    </td>
                    <td className="py-2.5 px-3">
                      {isCatAnalyzed ? (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800">
                          analyzed
                        </span>
                      ) : (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                          {catComp.previous_status === "not_analyzed" && catComp.current_status === "not_analyzed"
                            ? "not analyzed"
                            : `${catComp.previous_status} -> ${catComp.current_status}`}
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono text-slate-400">
                      {catComp.previous_score !== null && catComp.previous_score !== undefined
                        ? catComp.previous_score
                        : "—"}
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono text-slate-400">
                      {catComp.current_score !== null && catComp.current_score !== undefined
                        ? catComp.current_score
                        : "—"}
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono">
                      {catComp.score_delta !== null && catComp.score_delta !== undefined ? (
                        <span
                          className={`font-semibold ${
                            catComp.score_delta > 0
                              ? "text-rose-400"
                              : catComp.score_delta < 0
                              ? "text-emerald-400"
                              : "text-slate-400"
                          }`}
                        >
                          {catComp.score_delta > 0 ? `+${catComp.score_delta}` : catComp.score_delta}
                        </span>
                      ) : (
                        <span className="text-slate-500 italic">n/a</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono">
                      <span
                        className={`${
                          catComp.finding_delta > 0
                            ? "text-amber-400 font-semibold"
                            : catComp.finding_delta < 0
                            ? "text-emerald-400 font-semibold"
                            : "text-slate-400"
                        }`}
                      >
                        {catComp.finding_delta > 0
                          ? `+${catComp.finding_delta}`
                          : catComp.finding_delta}
                      </span>
                      <span className="text-slate-500 text-[10px] ml-1">
                        ({catComp.previous_finding_count} → {catComp.current_finding_count})
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Dynamic Rule-Level Deltas (if any changes) */}
      {rule_comparisons.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-emerald-400" />
            <span>Rule-Level Shift ({rule_comparisons.length} rules changed)</span>
          </h3>

          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-900/80 border-b border-border text-slate-400 font-mono">
                  <th className="py-2 px-3">Rule ID</th>
                  <th className="py-2 px-3">Title</th>
                  <th className="py-2 px-3">Category</th>
                  <th className="py-2 px-3 text-right">Previous</th>
                  <th className="py-2 px-3 text-right">Current</th>
                  <th className="py-2 px-3 text-right">Delta</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {rule_comparisons.map((r: RuleComparison) => (
                  <tr key={r.rule_id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-2 px-3 font-mono text-emerald-400 font-medium">
                      {r.rule_id}
                    </td>
                    <td className="py-2 px-3 text-slate-200">{r.title}</td>
                    <td className="py-2 px-3 text-slate-400">
                      {getCategoryDisplayName(r.category)}
                    </td>
                    <td className="py-2 px-3 text-right font-mono text-slate-400">
                      {r.previous_count}
                    </td>
                    <td className="py-2 px-3 text-right font-mono text-slate-400">
                      {r.current_count}
                    </td>
                    <td className="py-2 px-3 text-right font-mono font-semibold">
                      <span
                        className={
                          r.delta > 0
                            ? "text-amber-400"
                            : r.delta < 0
                            ? "text-emerald-400"
                            : "text-slate-400"
                        }
                      >
                        {r.delta > 0 ? `+${r.delta}` : r.delta}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Findings Detail Tabs (New, Resolved, Persistent) */}
      <div className="space-y-4 pt-2">
        <div className="flex items-center gap-2 border-b border-border pb-2">
          <button
            onClick={() => setActiveTab("new")}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors flex items-center gap-1.5 ${
              activeTab === "new"
                ? "bg-amber-950/60 border border-amber-800 text-amber-300"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>New Findings ({comparison.new_findings.length})</span>
          </button>

          <button
            onClick={() => setActiveTab("resolved")}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors flex items-center gap-1.5 ${
              activeTab === "resolved"
                ? "bg-emerald-950/60 border border-emerald-800 text-emerald-300"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Resolved Findings ({comparison.resolved_findings.length})</span>
          </button>

          <button
            onClick={() => setActiveTab("persistent")}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors flex items-center gap-1.5 ${
              activeTab === "persistent"
                ? "bg-slate-800 border border-slate-700 text-slate-200"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Persistent Findings ({comparison.persistent_findings.length})</span>
          </button>
        </div>

        {/* Tab Content */}
        {activeTab === "new" && (
          <div className="space-y-2">
            {comparison.new_findings.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 bg-slate-900/40 rounded-lg border border-border">
                No new debt findings were introduced in this scan.
              </div>
            ) : (
              comparison.new_findings.map((item: ComparisonFindingItem) => (
                <div
                  key={item.id}
                  className="bg-slate-900/60 border border-amber-900/40 rounded-lg p-3 flex items-start justify-between gap-3 text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-emerald-400 font-semibold">
                        {item.rule_id}
                      </span>
                      <span className="font-medium text-white">{item.title}</span>
                      <span className={`text-[10px] px-1.5 py-0.2 rounded font-semibold border ${getSeverityColor(item.severity)}`}>
                        {item.severity}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 font-mono text-[11px] text-slate-400">
                      <FileCode className="w-3.5 h-3.5 text-slate-500" />
                      <span>{item.file}</span>
                      <span className="text-slate-600">:</span>
                      <span>L{item.line_start}-{item.line_end}</span>
                      {item.symbol && (
                        <>
                          <span className="text-slate-600">•</span>
                          <span className="text-slate-300">{item.symbol}</span>
                        </>
                      )}
                    </div>
                  </div>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-amber-950/70 border border-amber-800 text-amber-300 font-mono">
                    NEW
                  </span>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === "resolved" && (
          <div className="space-y-2">
            {comparison.resolved_findings.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 bg-slate-900/40 rounded-lg border border-border">
                No previous debt findings were resolved between these scans.
              </div>
            ) : (
              comparison.resolved_findings.map((item: ComparisonFindingItem) => (
                <div
                  key={item.id}
                  className="bg-slate-900/60 border border-emerald-900/40 rounded-lg p-3 flex items-start justify-between gap-3 text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-emerald-400 font-semibold">
                        {item.rule_id}
                      </span>
                      <span className="font-medium text-white">{item.title}</span>
                      <span className={`text-[10px] px-1.5 py-0.2 rounded font-semibold border ${getSeverityColor(item.severity)}`}>
                        {item.severity}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 font-mono text-[11px] text-slate-400">
                      <FileCode className="w-3.5 h-3.5 text-slate-500" />
                      <span>{item.file}</span>
                      <span className="text-slate-600">:</span>
                      <span>L{item.line_start}-{item.line_end}</span>
                      {item.symbol && (
                        <>
                          <span className="text-slate-600">•</span>
                          <span className="text-slate-300">{item.symbol}</span>
                        </>
                      )}
                    </div>
                    <p className="text-[11px] text-emerald-400 italic">
                      {item.resolution_status || "No longer detected since previous scan"}
                    </p>
                  </div>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950/70 border border-emerald-800 text-emerald-300 font-mono">
                    RESOLVED
                  </span>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === "persistent" && (
          <div className="space-y-2">
            {comparison.persistent_findings.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 bg-slate-900/40 rounded-lg border border-border">
                No persistent findings between these scans.
              </div>
            ) : (
              comparison.persistent_findings.map((item: ComparisonFindingItem) => (
                <div
                  key={item.id}
                  className="bg-slate-900/40 border border-border rounded-lg p-3 flex items-start justify-between gap-3 text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-emerald-400 font-semibold">
                        {item.rule_id}
                      </span>
                      <span className="font-medium text-white">{item.title}</span>
                      <span className={`text-[10px] px-1.5 py-0.2 rounded font-semibold border ${getSeverityColor(item.severity)}`}>
                        {item.severity}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 font-mono text-[11px] text-slate-400">
                      <FileCode className="w-3.5 h-3.5 text-slate-500" />
                      <span>{item.file}</span>
                      <span className="text-slate-600">:</span>
                      <span>L{item.line_start}-{item.line_end}</span>
                      {item.symbol && (
                        <>
                          <span className="text-slate-600">•</span>
                          <span className="text-slate-300">{item.symbol}</span>
                        </>
                      )}
                    </div>
                  </div>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono">
                    PERSISTENT
                  </span>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}

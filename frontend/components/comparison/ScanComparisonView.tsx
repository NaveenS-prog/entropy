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

  const delta = summary.score_delta;
  const isIncreased = delta > 0;
  const isDecreased = delta < 0;

  return (
    <div className="bg-card border border-border rounded-xl p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-border">
        <div className="space-y-0.5">
          <div className="flex items-center gap-2">
            <div className="h-7 w-7 rounded-md bg-ink-800 border border-border flex items-center justify-center text-ink-300">
              <GitCompare className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-white tracking-tight">
                Scan comparison
              </h2>
              <p className="text-xs text-ink-400">
                Deterministic debt differential and lifecycle analysis
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-xs font-mono bg-ink-850 border border-border px-3 py-1.5 rounded-md">
            <div className="text-ink-400">
              <span className="text-[10px] text-ink-500 uppercase block">Baseline</span>
              {comparison.previous_scan_id.slice(0, 8)}
            </div>
            <ArrowRight className="w-3.5 h-3.5 text-ink-500" />
            <div className="text-emerald-400">
              <span className="text-[10px] text-ink-500 uppercase block">Current</span>
              {comparison.current_scan_id.slice(0, 8)}
            </div>
          </div>

          {onClose && (
            <button
              onClick={onClose}
              className="text-xs px-3 py-1.5 rounded-md bg-ink-800 hover:bg-ink-700 text-ink-300 hover:text-white transition-colors border border-border"
            >
              Close
            </button>
          )}
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Score Delta */}
        <div className="bg-ink-850 border border-border rounded-lg p-3.5 space-y-1">
          <div className="flex items-center justify-between text-xs text-ink-400">
            <span>Score delta</span>
            {isIncreased ? (
              <TrendingUp className="w-3.5 h-3.5 text-red-400" />
            ) : isDecreased ? (
              <TrendingDown className="w-3.5 h-3.5 text-emerald-400" />
            ) : (
              <Minus className="w-3.5 h-3.5 text-ink-400" />
            )}
          </div>
          <div className="flex items-baseline gap-1.5">
            <span
              className={`text-xl font-semibold font-mono tabular-nums ${
                isIncreased
                  ? "text-red-400"
                  : isDecreased
                  ? "text-emerald-400"
                  : "text-ink-200"
              }`}
            >
              {isIncreased ? `+${delta}` : delta}
            </span>
            <span className="text-xs text-ink-500 font-mono">pts</span>
          </div>
          <p className="text-[11px] text-ink-400 leading-tight">
            {score_comparison.explanation}
          </p>
        </div>

        {/* New Findings */}
        <div
          onClick={() => setActiveTab("new")}
          className={`bg-ink-850 border rounded-lg p-3.5 space-y-1 cursor-pointer transition-colors ${
            activeTab === "new" ? "border-amber-500/60 bg-ink-800" : "border-border hover:border-ink-600"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-ink-400">
            <span>New findings</span>
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="text-xl font-semibold font-mono tabular-nums text-amber-300">
              +{summary.new_findings_count}
            </span>
            <span className="text-xs text-ink-500 font-mono">introduced</span>
          </div>
          <p className="text-[11px] text-ink-400 leading-tight">
            Patterns not in baseline scan
          </p>
        </div>

        {/* Resolved Findings */}
        <div
          onClick={() => setActiveTab("resolved")}
          className={`bg-ink-850 border rounded-lg p-3.5 space-y-1 cursor-pointer transition-colors ${
            activeTab === "resolved" ? "border-emerald-500/60 bg-ink-800" : "border-border hover:border-ink-600"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-ink-400">
            <span>Resolved findings</span>
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="text-xl font-semibold font-mono tabular-nums text-emerald-400">
              -{summary.resolved_findings_count}
            </span>
            <span className="text-xs text-ink-500 font-mono">eliminated</span>
          </div>
          <p className="text-[11px] text-ink-400 leading-tight">
            Previously detected debt cleared
          </p>
        </div>

        {/* Persistent Findings */}
        <div
          onClick={() => setActiveTab("persistent")}
          className={`bg-ink-850 border rounded-lg p-3.5 space-y-1 cursor-pointer transition-colors ${
            activeTab === "persistent" ? "border-ink-500 bg-ink-800" : "border-border hover:border-ink-600"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-ink-400">
            <span>Persistent findings</span>
            <Layers className="w-3.5 h-3.5 text-ink-400" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="text-xl font-semibold font-mono tabular-nums text-ink-200">
              {summary.persistent_findings_count}
            </span>
            <span className="text-xs text-ink-500 font-mono">retained</span>
          </div>
          <p className="text-[11px] text-ink-400 leading-tight">
            Patterns across both scans
          </p>
        </div>
      </div>

      {/* Category Deltas Table */}
      <div className="space-y-3">
        <h3 className="text-xs font-medium text-ink-200 uppercase tracking-wider flex items-center gap-2">
          <Layers className="w-3.5 h-3.5 text-ink-400" />
          <span>Category deltas</span>
        </h3>

        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-ink-850 border-b border-border text-ink-400 font-mono text-[11px]">
                <th className="py-2.5 px-3 font-normal">Category</th>
                <th className="py-2.5 px-3 font-normal">Status</th>
                <th className="py-2.5 px-3 text-right font-normal">Baseline</th>
                <th className="py-2.5 px-3 text-right font-normal">Current</th>
                <th className="py-2.5 px-3 text-right font-normal">Score delta</th>
                <th className="py-2.5 px-3 text-right font-normal">Findings delta</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border font-mono text-xs">
              {Object.entries(category_comparisons).map(([catKey, catComp]: [string, CategoryComparison]) => {
                const displayName = getCategoryDisplayName(catComp.category);
                const isCatAnalyzed =
                  catComp.previous_status === "analyzed" && catComp.current_status === "analyzed";

                return (
                  <tr key={catKey} className="hover:bg-ink-850/40 transition-colors">
                    <td className="py-2.5 px-3 font-sans font-medium text-ink-100">
                      {displayName}
                    </td>
                    <td className="py-2.5 px-3">
                      {isCatAnalyzed ? (
                        <span className="text-[11px] px-1.5 py-0.5 rounded bg-ink-800 text-emerald-400 border border-border">
                          analyzed
                        </span>
                      ) : (
                        <span className="text-[11px] px-1.5 py-0.5 rounded bg-ink-800 text-ink-400 border border-border">
                          {catComp.previous_status === "not_analyzed" && catComp.current_status === "not_analyzed"
                            ? "not analyzed"
                            : `${catComp.previous_status} → ${catComp.current_status}`}
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-right text-ink-400 tabular-nums">
                      {catComp.previous_score !== null && catComp.previous_score !== undefined
                        ? catComp.previous_score
                        : "—"}
                    </td>
                    <td className="py-2.5 px-3 text-right text-ink-400 tabular-nums">
                      {catComp.current_score !== null && catComp.current_score !== undefined
                        ? catComp.current_score
                        : "—"}
                    </td>
                    <td className="py-2.5 px-3 text-right tabular-nums">
                      {catComp.score_delta !== null && catComp.score_delta !== undefined ? (
                        <span
                          className={`font-medium ${
                            catComp.score_delta > 0
                              ? "text-red-400"
                              : catComp.score_delta < 0
                              ? "text-emerald-400"
                              : "text-ink-400"
                          }`}
                        >
                          {catComp.score_delta > 0 ? `+${catComp.score_delta}` : catComp.score_delta}
                        </span>
                      ) : (
                        <span className="text-ink-500 italic">n/a</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-right tabular-nums">
                      <span
                        className={
                          catComp.finding_delta > 0
                            ? "text-amber-400 font-medium"
                            : catComp.finding_delta < 0
                            ? "text-emerald-400 font-medium"
                            : "text-ink-400"
                        }
                      >
                        {catComp.finding_delta > 0
                          ? `+${catComp.finding_delta}`
                          : catComp.finding_delta}
                      </span>
                      <span className="text-ink-500 text-[10px] ml-1">
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

      {/* Dynamic Rule-Level Deltas */}
      {rule_comparisons.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-xs font-medium text-ink-200 uppercase tracking-wider flex items-center gap-2">
            <ShieldAlert className="w-3.5 h-3.5 text-ink-400" />
            <span>Rule changes ({rule_comparisons.length})</span>
          </h3>

          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-ink-850 border-b border-border text-ink-400 font-mono text-[11px]">
                  <th className="py-2 px-3 font-normal">Rule ID</th>
                  <th className="py-2 px-3 font-normal">Title</th>
                  <th className="py-2 px-3 font-normal">Category</th>
                  <th className="py-2 px-3 text-right font-normal">Previous</th>
                  <th className="py-2 px-3 text-right font-normal">Current</th>
                  <th className="py-2 px-3 text-right font-normal">Delta</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border font-mono text-xs">
                {rule_comparisons.map((r: RuleComparison) => (
                  <tr key={r.rule_id} className="hover:bg-ink-850/40 transition-colors">
                    <td className="py-2 px-3 text-emerald-400 font-medium">
                      {r.rule_id}
                    </td>
                    <td className="py-2 px-3 font-sans text-ink-100">{r.title}</td>
                    <td className="py-2 px-3 font-sans text-ink-400">
                      {getCategoryDisplayName(r.category)}
                    </td>
                    <td className="py-2 px-3 text-right text-ink-400 tabular-nums">
                      {r.previous_count}
                    </td>
                    <td className="py-2 px-3 text-right text-ink-400 tabular-nums">
                      {r.current_count}
                    </td>
                    <td className="py-2 px-3 text-right font-medium tabular-nums">
                      <span
                        className={
                          r.delta > 0
                            ? "text-amber-400"
                            : r.delta < 0
                            ? "text-emerald-400"
                            : "text-ink-400"
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

      {/* Findings Detail Tabs */}
      <div className="space-y-3 pt-2">
        <div className="flex items-center gap-1.5 border-b border-border pb-2">
          <button
            onClick={() => setActiveTab("new")}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 ${
              activeTab === "new"
                ? "bg-ink-800 text-white border border-border"
                : "text-ink-400 hover:text-white"
            }`}
          >
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            <span>New findings ({comparison.new_findings.length})</span>
          </button>

          <button
            onClick={() => setActiveTab("resolved")}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 ${
              activeTab === "resolved"
                ? "bg-ink-800 text-white border border-border"
                : "text-ink-400 hover:text-white"
            }`}
          >
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>Resolved findings ({comparison.resolved_findings.length})</span>
          </button>

          <button
            onClick={() => setActiveTab("persistent")}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center gap-1.5 ${
              activeTab === "persistent"
                ? "bg-ink-800 text-white border border-border"
                : "text-ink-400 hover:text-white"
            }`}
          >
            <Layers className="w-3.5 h-3.5 text-ink-400" />
            <span>Persistent findings ({comparison.persistent_findings.length})</span>
          </button>
        </div>

        {/* Tab Content */}
        {activeTab === "new" && (
          <div className="space-y-2">
            {comparison.new_findings.length === 0 ? (
              <div className="p-6 text-center text-xs text-ink-500 bg-ink-850 rounded-lg border border-border">
                No new findings introduced in this scan
              </div>
            ) : (
              comparison.new_findings.map((item: ComparisonFindingItem) => (
                <div
                  key={item.id}
                  className="bg-ink-850 border border-border rounded-lg p-3 flex items-start justify-between gap-3 text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-emerald-400 font-medium">
                        {item.rule_id}
                      </span>
                      <span className="font-medium text-white">{item.title}</span>
                      <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono border ${getSeverityColor(item.severity)}`}>
                        {item.severity}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 font-mono text-[11px] text-ink-400">
                      <FileCode className="w-3 h-3 text-ink-500" />
                      <span>{item.file}</span>
                      <span className="text-ink-600">:</span>
                      <span>L{item.line_start}-{item.line_end}</span>
                      {item.symbol && (
                        <>
                          <span className="text-ink-600">•</span>
                          <span className="text-ink-300">{item.symbol}</span>
                        </>
                      )}
                    </div>
                  </div>
                  <span className="text-[11px] px-2 py-0.5 rounded bg-ink-800 border border-border text-amber-300 font-mono">
                    New
                  </span>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === "resolved" && (
          <div className="space-y-2">
            {comparison.resolved_findings.length === 0 ? (
              <div className="p-6 text-center text-xs text-ink-500 bg-ink-850 rounded-lg border border-border">
                No findings resolved between these scans
              </div>
            ) : (
              comparison.resolved_findings.map((item: ComparisonFindingItem) => (
                <div
                  key={item.id}
                  className="bg-ink-850 border border-border rounded-lg p-3 flex items-start justify-between gap-3 text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-emerald-400 font-medium">
                        {item.rule_id}
                      </span>
                      <span className="font-medium text-white">{item.title}</span>
                      <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono border ${getSeverityColor(item.severity)}`}>
                        {item.severity}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 font-mono text-[11px] text-ink-400">
                      <FileCode className="w-3 h-3 text-ink-500" />
                      <span>{item.file}</span>
                      <span className="text-ink-600">:</span>
                      <span>L{item.line_start}-{item.line_end}</span>
                      {item.symbol && (
                        <>
                          <span className="text-ink-600">•</span>
                          <span className="text-ink-300">{item.symbol}</span>
                        </>
                      )}
                    </div>
                    <p className="text-[11px] text-emerald-400">
                      {item.resolution_status || "No longer detected"}
                    </p>
                  </div>
                  <span className="text-[11px] px-2 py-0.5 rounded bg-ink-800 border border-border text-emerald-400 font-mono">
                    Resolved
                  </span>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === "persistent" && (
          <div className="space-y-2">
            {comparison.persistent_findings.length === 0 ? (
              <div className="p-6 text-center text-xs text-ink-500 bg-ink-850 rounded-lg border border-border">
                No persistent findings between these scans
              </div>
            ) : (
              comparison.persistent_findings.map((item: ComparisonFindingItem) => (
                <div
                  key={item.id}
                  className="bg-ink-850 border border-border rounded-lg p-3 flex items-start justify-between gap-3 text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-emerald-400 font-medium">
                        {item.rule_id}
                      </span>
                      <span className="font-medium text-white">{item.title}</span>
                      <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono border ${getSeverityColor(item.severity)}`}>
                        {item.severity}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 font-mono text-[11px] text-ink-400">
                      <FileCode className="w-3 h-3 text-ink-500" />
                      <span>{item.file}</span>
                      <span className="text-ink-600">:</span>
                      <span>L{item.line_start}-{item.line_end}</span>
                      {item.symbol && (
                        <>
                          <span className="text-ink-600">•</span>
                          <span className="text-ink-300">{item.symbol}</span>
                        </>
                      )}
                    </div>
                  </div>
                  <span className="text-[11px] px-2 py-0.5 rounded bg-ink-800 border border-border text-ink-300 font-mono">
                    Persistent
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

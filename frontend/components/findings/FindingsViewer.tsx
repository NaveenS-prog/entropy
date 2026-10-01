"use client";

import { useState } from "react";
import { DebtCategory, Finding, Severity } from "@/types";
import { getSeverityBadge } from "@/lib/utils";
import {
  Code,
  AlertCircle,
  Lightbulb,
  Search,
  ChevronDown,
  ChevronUp,
  ShieldCheck,
  ShieldAlert,
  Hash,
} from "lucide-react";

interface FindingsViewerProps {
  scanId: string;
  findings: Finding[];
  selectedCategory?: DebtCategory | null;
  isLoading?: boolean;
}

const ERROR_HANDLING_RULES = [
  { id: "all", label: "All Rules" },
  { id: "ENT-ERR-001", label: "ENT-ERR-001 (Bare Except)" },
  { id: "ENT-ERR-002", label: "ENT-ERR-002 (Broad Handler)" },
  { id: "ENT-ERR-003", label: "ENT-ERR-003 (Empty Handler)" },
  { id: "ENT-ERR-004", label: "ENT-ERR-004 (Silently Swallowed)" },
  { id: "ENT-ERR-005", label: "ENT-ERR-005 (Generic Fallback)" },
];

export function FindingsViewer({
  scanId: _scanId,
  findings,
  selectedCategory,
  isLoading = false,
}: FindingsViewerProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | "all">("all");
  const [selectedRule, setSelectedRule] = useState<string>("all");
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});

  const toggleExpand = (id: string) => {
    setExpandedFindings((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const expandAll = () => {
    const next: Record<string, boolean> = {};
    filtered.forEach((f) => {
      next[f.id] = true;
    });
    setExpandedFindings(next);
  };

  const collapseAll = () => {
    setExpandedFindings({});
  };

  // Filter findings
  const filtered = findings.filter((f) => {
    if (selectedCategory && f.category !== selectedCategory) return false;
    if (selectedSeverity !== "all" && f.severity !== selectedSeverity) return false;
    if (selectedRule !== "all" && f.rule_id !== selectedRule) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const inTitle = f.title.toLowerCase().includes(term);
      const inFile = f.file.toLowerCase().includes(term);
      const inRule = f.rule_id.toLowerCase().includes(term);
      const inSymbol = f.symbol?.toLowerCase().includes(term);
      if (!inTitle && !inFile && !inRule && !inSymbol) return false;
    }
    return true;
  });

  return (
    <div className="bg-card border border-border rounded-xl p-6 shadow-sm">
      {/* Header and Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-5">
        <div>
          <h2 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-amber-400" />
            <span>Error Handling Debt Findings</span>
            <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">
              {filtered.length} of {findings.length}
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic AST findings: bare clauses, broad handlers, empty blocks, silent swallows, and generic fallbacks.
          </p>
        </div>

        {/* Filter Toolbar */}
        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Search box */}
          <div className="relative">
            <Search className="h-3.5 w-3.5 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search file, rule, symbol..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 w-48 sm:w-56 font-mono"
            />
          </div>

          {/* Rule Filter */}
          <select
            value={selectedRule}
            onChange={(e) => setSelectedRule(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-emerald-500 font-mono cursor-pointer"
          >
            {ERROR_HANDLING_RULES.map((r) => (
              <option key={r.id} value={r.id}>
                {r.label}
              </option>
            ))}
          </select>

          {/* Severity selector */}
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value as Severity | "all")}
            className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-emerald-500 capitalize cursor-pointer"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>

          {/* Expand/Collapse All */}
          {filtered.length > 0 && (
            <div className="flex items-center gap-1 pl-1">
              <button
                type="button"
                onClick={expandAll}
                className="text-[11px] text-slate-400 hover:text-white px-2 py-1 rounded bg-slate-800 border border-slate-700"
              >
                Expand All
              </button>
              <button
                type="button"
                onClick={collapseAll}
                className="text-[11px] text-slate-400 hover:text-white px-2 py-1 rounded bg-slate-800 border border-slate-700"
              >
                Collapse All
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Findings List */}
      <div className="mt-5 space-y-3">
        {isLoading ? (
          <div className="text-center py-12 text-slate-400 text-xs font-mono">
            Analyzing Python AST for Error Handling Debt...
          </div>
        ) : findings.length === 0 ? (
          <div className="text-center py-12 px-4 rounded-xl border border-dashed border-emerald-900/60 bg-emerald-950/20">
            <ShieldCheck className="h-10 w-10 text-emerald-400 mx-auto mb-2.5 opacity-90" />
            <h3 className="text-sm font-semibold text-emerald-300">Clean Exception Architecture</h3>
            <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
              No Error Handling Debt findings detected by the currently enabled rules.
            </p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-10 text-slate-500 text-xs">
            No findings match your filter criteria.
          </div>
        ) : (
          filtered.map((finding) => {
            const isExpanded = !!expandedFindings[finding.id];
            const badge = getSeverityBadge(finding.severity);

            return (
              <div
                key={finding.id}
                className="border border-slate-800 rounded-lg bg-slate-950/40 overflow-hidden transition-all hover:border-slate-700"
              >
                {/* Header row */}
                <div
                  onClick={() => toggleExpand(finding.id)}
                  className="p-3.5 flex items-center justify-between gap-3 cursor-pointer select-none"
                >
                  <div className="flex items-start md:items-center gap-2.5 flex-1 flex-wrap">
                    <span
                      className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border font-mono ${badge.bg} ${badge.text} ${badge.border}`}
                    >
                      {finding.severity}
                    </span>

                    <span className="text-[10px] uppercase font-mono font-medium text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                      {finding.rule_id}
                    </span>

                    <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                      {finding.confidence} confidence
                    </span>

                    <h3 className="text-xs font-semibold text-white tracking-tight">{finding.title}</h3>

                    <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
                      <span className="text-slate-600">•</span>
                      <span className="text-slate-300">
                        {finding.file}:{finding.line_start}-{finding.line_end}
                      </span>
                      {finding.symbol && (
                        <span className="text-emerald-400/90 bg-emerald-950/40 px-1.5 py-0.5 rounded border border-emerald-900/50 text-[11px]">
                          {finding.symbol}
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleExpand(finding.id);
                      }}
                      className="p-1 rounded text-slate-400 hover:text-white"
                      aria-label="Toggle details"
                    >
                      {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                    </button>
                  </div>
                </div>

                {/* Expanded details */}
                {isExpanded && (
                  <div className="p-4 pt-2 border-t border-slate-800/80 mt-1 space-y-3.5 text-xs">
                    {/* Description */}
                    <p className="text-slate-300 leading-relaxed">{finding.description}</p>

                    {/* Code Evidence snippet */}
                    {finding.evidence && finding.evidence.content && (
                      <div>
                        <div className="flex items-center gap-1.5 text-slate-400 mb-1 font-mono text-[11px]">
                          <Code className="h-3.5 w-3.5 text-emerald-400" />
                          <span>
                            Verbatim Code Evidence ({finding.file} lines {finding.evidence.line_start}-{finding.evidence.line_end})
                          </span>
                        </div>
                        <div className="bg-slate-950 rounded-lg p-3 border border-slate-800 font-mono text-xs overflow-x-auto text-slate-300">
                          <pre>
                            {finding.evidence.content.split("\n").map((line, idx) => {
                              const lineNo = finding.evidence.line_start + idx;
                              const isHighlighted = finding.evidence.highlight_lines.includes(lineNo);
                              return (
                                <div
                                  key={idx}
                                  className={`flex ${
                                    isHighlighted
                                      ? "bg-red-500/15 text-red-200 border-l-2 border-red-500 pl-2"
                                      : "pl-2.5 text-slate-400"
                                  }`}
                                >
                                  <span className="w-8 select-none text-slate-600 text-right pr-3 font-mono text-[11px]">
                                    {lineNo}
                                  </span>
                                  <span className="font-mono">{line}</span>
                                </div>
                              );
                            })}
                          </pre>
                        </div>
                      </div>
                    )}

                    {/* Impact & Recommendation Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div className="p-3 rounded-lg bg-orange-950/20 border border-orange-900/40">
                        <div className="flex items-center gap-1.5 font-semibold text-orange-400 mb-1">
                          <AlertCircle className="h-3.5 w-3.5" />
                          <span>Accumulated Debt Impact</span>
                        </div>
                        <p className="text-slate-300 leading-relaxed">{finding.impact}</p>
                      </div>

                      <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-900/40">
                        <div className="flex items-center gap-1.5 font-semibold text-emerald-400 mb-1">
                          <Lightbulb className="h-3.5 w-3.5" />
                          <span>Architectural Recommendation</span>
                        </div>
                        <p className="text-slate-300 leading-relaxed">{finding.recommendation}</p>
                      </div>
                    </div>

                    {/* Deterministic Fingerprint / Audit Footer */}
                    <div className="pt-1 flex items-center justify-between text-[10px] font-mono text-slate-500 border-t border-slate-900">
                      <div className="flex items-center gap-2">
                        <Hash className="h-3 w-3 text-slate-600" />
                        <span>Finding ID: {finding.id}</span>
                      </div>
                      <div>
                        <span>Fingerprint: {finding.fingerprint}</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

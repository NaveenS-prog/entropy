"use client";

import { useState } from "react";
import { DebtCategory, Finding, FindingExplanation, Severity } from "@/types";
import { getSeverityBadge } from "@/lib/utils";
import { explainFinding } from "@/lib/api";
import {
  Code,
  FileText,
  AlertCircle,
  Lightbulb,
  Search,
  Sparkles,
  ChevronDown,
  ChevronUp,
  Tag,
} from "lucide-react";

interface FindingsViewerProps {
  scanId: string;
  findings: Finding[];
  selectedCategory?: DebtCategory | null;
}

export function FindingsViewer({ scanId, findings, selectedCategory }: FindingsViewerProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | "all">("all");
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});
  const [explanations, setExplanations] = useState<Record<string, FindingExplanation>>({});
  const [loadingExplains, setLoadingExplains] = useState<Record<string, boolean>>({});

  const toggleExpand = (id: string) => {
    setExpandedFindings((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleExplain = async (findingId: string) => {
    if (explanations[findingId]) return;
    try {
      setLoadingExplains((prev) => ({ ...prev, [findingId]: true }));
      const result = await explainFinding(scanId, findingId);
      setExplanations((prev) => ({ ...prev, [findingId]: result }));
    } catch (err) {
      console.error("Failed to explain finding:", err);
    } finally {
      setLoadingExplains((prev) => ({ ...prev, [findingId]: false }));
    }
  };

  // Filter findings
  const filtered = findings.filter((f) => {
    if (selectedCategory && f.category !== selectedCategory) return false;
    if (selectedSeverity !== "all" && f.severity !== selectedSeverity) return false;
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
    <div className="mt-8 bg-card border border-border rounded-xl p-6 shadow-xl">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-5">
        <div>
          <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
            <span>Silent Security Debt Findings</span>
            <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">
              {filtered.length} of {findings.length}
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Observable architectural patterns traceable to source code
          </p>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3 flex-wrap">
          {/* Search box */}
          <div className="relative">
            <Search className="h-3.5 w-3.5 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search findings, files, symbols..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 w-56"
            />
          </div>

          {/* Severity selector */}
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value as Severity | "all")}
            className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-emerald-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
      </div>

      {/* Findings List */}
      <div className="mt-5 space-y-4">
        {filtered.length === 0 ? (
          <div className="text-center py-12 text-slate-500 text-sm">
            No silent debt findings matching the selected filters.
          </div>
        ) : (
          filtered.map((finding) => {
            const isExpanded = !!expandedFindings[finding.id];
            const badge = getSeverityBadge(finding.severity);
            const explanation = explanations[finding.id];
            const isExplaining = loadingExplains[finding.id];

            return (
              <div
                key={finding.id}
                className="border border-border rounded-lg bg-slate-950/40 overflow-hidden transition-all hover:border-slate-700"
              >
                {/* Header row */}
                <div
                  onClick={() => toggleExpand(finding.id)}
                  className="p-4 flex items-center justify-between gap-4 cursor-pointer select-none"
                >
                  <div className="flex items-start md:items-center gap-3.5 flex-1 flex-wrap">
                    <span
                      className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border font-mono ${badge.bg} ${badge.text} ${badge.border}`}
                    >
                      {finding.severity}
                    </span>

                    <span className="text-xs font-mono font-medium text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                      {finding.rule_id}
                    </span>

                    <h3 className="text-sm font-semibold text-white tracking-tight">{finding.title}</h3>

                    <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
                      <span className="text-slate-500">•</span>
                      <span>
                        {finding.file}:{finding.line_start}-{finding.line_end}
                      </span>
                      {finding.symbol && (
                        <span className="text-emerald-400/90 bg-emerald-950/40 px-1.5 py-0.2 rounded border border-emerald-900/50">
                          {finding.symbol}
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleExpand(finding.id);
                      }}
                      className="p-1 rounded text-slate-400 hover:text-white"
                    >
                      {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                    </button>
                  </div>
                </div>

                {/* Expanded details */}
                {isExpanded && (
                  <div className="p-4 pt-0 border-t border-border/60 mt-2 space-y-4">
                    {/* Description */}
                    <p className="text-xs text-slate-300 leading-relaxed">{finding.description}</p>

                    {/* Code Evidence snippet */}
                    <div>
                      <div className="flex items-center gap-1.5 text-xs text-slate-400 mb-1.5 font-mono">
                        <Code className="h-3.5 w-3.5 text-emerald-400" />
                        <span>Verbatim Code Evidence ({finding.file})</span>
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
                                    ? "bg-red-500/10 text-red-200 border-l-2 border-red-500 pl-2"
                                    : "pl-2.5 text-slate-400"
                                }`}
                              >
                                <span className="w-8 select-none text-slate-600 text-right pr-3">
                                  {lineNo}
                                </span>
                                <span>{line}</span>
                              </div>
                            );
                          })}
                        </pre>
                      </div>
                    </div>

                    {/* Impact & Recommendation Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
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

                    {/* Explanatory AI Layer (Grounding, no hallucinations) */}
                    <div className="pt-2">
                      {!explanation ? (
                        <button
                          onClick={() => handleExplain(finding.id)}
                          disabled={isExplaining}
                          className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 transition-colors"
                        >
                          <Sparkles className="h-3.5 w-3.5 text-purple-400" />
                          <span>
                            {isExplaining ? "Synthesizing Architecture..." : "Grounded Architectural Analysis"}
                          </span>
                        </button>
                      ) : (
                        <div className="p-3.5 rounded-lg bg-purple-950/20 border border-purple-900/40 text-xs space-y-2">
                          <div className="flex items-center gap-1.5 font-semibold text-purple-300">
                            <Sparkles className="h-3.5 w-3.5" />
                            <span>Grounded Architectural Context</span>
                          </div>
                          <p className="text-slate-300 leading-relaxed">
                            {explanation.architectural_context}
                          </p>
                          <div className="text-slate-400 text-[11px]">
                            <strong className="text-purple-300">Long-term Hazard:</strong>{" "}
                            {explanation.maintenance_risk}
                          </div>
                        </div>
                      )}
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

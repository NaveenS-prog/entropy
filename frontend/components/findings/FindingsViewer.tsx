"use client";

import { useMemo, useState } from "react";
import { AIExplanation, DebtCategory, Finding, Severity } from "@/types";
import { getSeverityBadge } from "@/lib/utils";
import { requestAIExplanation } from "@/lib/api";
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
  Sparkles,
  Loader2,
  RefreshCw,
  Info,
} from "lucide-react";

interface FindingsViewerProps {
  scanId: string;
  findings: Finding[];
  selectedCategory?: DebtCategory | null;
  isLoading?: boolean;
}

export function FindingsViewer({
  scanId,
  findings,
  selectedCategory,
  isLoading = false,
}: FindingsViewerProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | "all">("all");
  const [selectedRule, setSelectedRule] = useState<string>("all");
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});

  // Phase 7: AI Explanation States
  const [aiExplanations, setAiExplanations] = useState<Record<string, AIExplanation>>({});
  const [loadingAI, setLoadingAI] = useState<Record<string, boolean>>({});
  const [aiErrors, setAiErrors] = useState<Record<string, string>>({});

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

  const handleRequestAIExplanation = async (findingId: string) => {
    setLoadingAI((prev) => ({ ...prev, [findingId]: true }));
    setAiErrors((prev) => {
      const copy = { ...prev };
      delete copy[findingId];
      return copy;
    });

    try {
      const result = await requestAIExplanation(findingId, scanId);
      setAiExplanations((prev) => ({ ...prev, [findingId]: result }));
    } catch (err: unknown) {
      const message =
        err instanceof Error
          ? err.message
          : "AI explanation is currently unavailable. The deterministic finding remains available.";
      setAiErrors((prev) => ({ ...prev, [findingId]: message }));
    } finally {
      setLoadingAI((prev) => ({ ...prev, [findingId]: false }));
    }
  };

  // Derive unique rules dynamically across all active categories (Phase 3, 5, 6)
  const uniqueRules = useMemo(() => {
    const ruleSet = new Set<string>();
    findings.forEach((f) => ruleSet.add(f.rule_id));
    return Array.from(ruleSet).sort();
  }, [findings]);

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
            <span>Architectural Debt Findings</span>
            <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">
              {filtered.length} of {findings.length}
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic AST findings across error handling, auth consistency, input validation, and secret hygiene.
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

          {/* Dynamic Rule Filter */}
          <select
            value={selectedRule}
            onChange={(e) => setSelectedRule(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-emerald-500 font-mono cursor-pointer"
          >
            <option value="all">All Rules ({uniqueRules.length})</option>
            {uniqueRules.map((ruleId) => (
              <option key={ruleId} value={ruleId}>
                {ruleId}
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
            Analyzing Python AST for Architectural & Security Debt...
          </div>
        ) : findings.length === 0 ? (
          <div className="text-center py-12 px-4 rounded-xl border border-dashed border-emerald-900/60 bg-emerald-950/20">
            <ShieldCheck className="h-10 w-10 text-emerald-400 mx-auto mb-2.5 opacity-90" />
            <h3 className="text-sm font-semibold text-emerald-300">Clean Architecture</h3>
            <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
              No architectural or security debt findings detected by active analyzers.
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
            const explanation = aiExplanations[finding.id];
            const isExplaining = !!loadingAI[finding.id];
            const aiError = aiErrors[finding.id];

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

                    {finding.is_suppressed && (
                      <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded border font-mono bg-purple-950/60 text-purple-300 border-purple-800">
                        SUPPRESSED
                      </span>
                    )}

                    {finding.status === "new" && (
                      <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded border font-mono bg-blue-950/60 text-blue-300 border-blue-800">
                        NEW
                      </span>
                    )}

                    {finding.status === "resolved" && (
                      <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded border font-mono bg-emerald-950/60 text-emerald-300 border-emerald-800">
                        RESOLVED
                      </span>
                    )}

                    {finding.status === "unchanged" && (
                      <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded border font-mono bg-slate-900 text-slate-400 border-slate-800">
                        UNCHANGED
                      </span>
                    )}

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
                  <div className="p-4 pt-2 border-t border-slate-800/80 mt-1 space-y-4 text-xs">
                    {/* Suppression metadata callout */}
                    {finding.is_suppressed && (
                      <div className="bg-purple-950/40 border border-purple-800/60 rounded-md p-3 text-purple-200">
                        <div className="font-semibold text-purple-300 flex items-center gap-1.5 mb-1">
                          <ShieldCheck className="h-4 w-4 text-purple-400" />
                          <span>Suppressed Finding ({finding.suppression_source || "manual"})</span>
                        </div>
                        <p className="text-purple-200/90 text-[11px] leading-relaxed">
                          {finding.suppression_reason || "This finding is suppressed and excluded from Entropy score and policy evaluations."}
                        </p>
                      </div>
                    )}

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

                    {/* Phase 7: AI Explanation & Remediation Section */}
                    <div className="pt-2 border-t border-slate-800/80">
                      {!explanation && !isExplaining && !aiError && (
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2 text-slate-400 text-xs">
                            <Sparkles className="h-4 w-4 text-indigo-400" />
                            <span>Need deeper architectural context or tailored remediation?</span>
                          </div>
                          <button
                            type="button"
                            onClick={() => handleRequestAIExplanation(finding.id)}
                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-xs shadow-sm transition-colors"
                          >
                            <Sparkles className="h-3.5 w-3.5" />
                            <span>Explain with AI</span>
                          </button>
                        </div>
                      )}

                      {/* Loading State */}
                      {isExplaining && (
                        <div className="p-4 rounded-lg bg-indigo-950/30 border border-indigo-900/50 flex items-center justify-center gap-2.5 text-indigo-200">
                          <Loader2 className="h-4 w-4 animate-spin text-indigo-400" />
                          <span className="font-mono text-xs">
                            Generating AI-assisted architectural explanation & remediation...
                          </span>
                        </div>
                      )}

                      {/* Error State */}
                      {aiError && (
                        <div className="p-3.5 rounded-lg bg-red-950/30 border border-red-900/50 flex items-center justify-between gap-3 text-red-200">
                          <div className="flex items-center gap-2">
                            <AlertCircle className="h-4 w-4 text-red-400 flex-shrink-0" />
                            <div className="text-xs">
                              <p className="font-semibold text-red-300">
                                AI explanation is currently unavailable.
                              </p>
                              <p className="text-slate-400 text-[11px] mt-0.5">
                                {aiError.includes("disabled")
                                  ? "AI explanations are not configured or disabled for this environment. Deterministic findings remain fully available."
                                  : aiError}
                              </p>
                            </div>
                          </div>
                          <button
                            type="button"
                            onClick={() => handleRequestAIExplanation(finding.id)}
                            className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] border border-slate-700"
                          >
                            <RefreshCw className="h-3 w-3" />
                            <span>Retry</span>
                          </button>
                        </div>
                      )}

                      {/* Structured Explanation Display */}
                      {explanation && (
                        <div className="p-4 rounded-xl border border-indigo-900/50 bg-indigo-950/20 space-y-3.5">
                          {/* Advisory Label Banner */}
                          <div className="flex items-center justify-between pb-2 border-b border-indigo-900/40">
                            <div className="flex items-center gap-2">
                              <Sparkles className="h-4 w-4 text-indigo-400" />
                              <span className="text-xs font-bold text-indigo-300 tracking-wider uppercase font-mono">
                                AI-Generated Explanation — Advisory Only
                              </span>
                            </div>
                            <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800 font-mono">
                              AI Confidence: {explanation.confidence}
                            </span>
                          </div>

                          {/* Executive Summary */}
                          <p className="text-xs text-indigo-200/90 leading-relaxed font-medium">
                            {explanation.summary}
                          </p>

                          {/* Why It Matters & Evidence Grounding */}
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
                              <div className="font-semibold text-slate-300 mb-1">Why This Matters</div>
                              <p className="text-slate-400 leading-relaxed">{explanation.why_it_matters}</p>
                            </div>

                            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
                              <div className="font-semibold text-slate-300 mb-1">Observable Evidence Grounding</div>
                              <p className="text-slate-400 leading-relaxed">{explanation.evidence_explanation}</p>
                            </div>
                          </div>

                          {/* Architectural Impact */}
                          <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 text-xs">
                            <div className="font-semibold text-slate-300 mb-1">Architectural Impact</div>
                            <p className="text-slate-400 leading-relaxed">{explanation.architectural_impact}</p>
                          </div>

                          {/* Remediation */}
                          <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-900/40 text-xs">
                            <div className="font-semibold text-emerald-400 mb-1">Remediation Steps</div>
                            <p className="text-slate-300 leading-relaxed">{explanation.remediation}</p>
                          </div>

                          {/* Suggested Pattern */}
                          {explanation.suggested_pattern && (
                            <div className="space-y-1">
                              <div className="text-[11px] font-mono text-slate-400">Suggested Pattern</div>
                              <div className="bg-slate-950 rounded-lg p-3 border border-slate-800 font-mono text-xs overflow-x-auto text-emerald-300">
                                <pre>{explanation.suggested_pattern}</pre>
                              </div>
                            </div>
                          )}

                          {/* Footer with Metadata & Mandatory Disclaimer */}
                          <div className="flex flex-wrap items-center justify-between text-[10px] font-mono text-slate-500 pt-2 border-t border-indigo-900/30 gap-2">
                            <span>
                              Model: {explanation.model} | Prompt v{explanation.prompt_version}
                            </span>
                            <span className="flex items-center gap-1">
                              <Info className="h-3 w-3 text-slate-500" />
                              {explanation.disclaimer}
                            </span>
                          </div>
                        </div>
                      )}
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

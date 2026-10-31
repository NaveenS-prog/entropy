"use client";

import { useMemo, useState } from "react";
import { AIExplanation, DebtCategory, Finding, Severity } from "@/types";
import { getSeverityBadge } from "@/lib/utils";
import { getStoredGeminiApiKey, requestAIExplanation, setStoredGeminiApiKey } from "@/lib/api";
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
  KeyRound,
  X,
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

  // AI Explanation States
  const [aiExplanations, setAiExplanations] = useState<Record<string, AIExplanation>>({});
  const [loadingAI, setLoadingAI] = useState<Record<string, boolean>>({});
  const [aiErrors, setAiErrors] = useState<Record<string, string>>({});
  const [inlineKeyInputs, setInlineKeyInputs] = useState<Record<string, string>>({});
  const [showKeyModal, setShowKeyModal] = useState(false);
  const [apiKeyInput, setApiKeyInput] = useState(() =>
    typeof window !== "undefined" ? getStoredGeminiApiKey() || "" : ""
  );

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

  const handleRequestAIExplanation = async (findingId: string, customKey?: string) => {
    setLoadingAI((prev) => ({ ...prev, [findingId]: true }));
    setAiErrors((prev) => {
      const copy = { ...prev };
      delete copy[findingId];
      return copy;
    });

    if (customKey) {
      setStoredGeminiApiKey(customKey);
      setApiKeyInput(customKey);
    }

    try {
      const result = await requestAIExplanation(findingId, scanId, customKey);
      setAiExplanations((prev) => ({ ...prev, [findingId]: result }));
    } catch (err: unknown) {
      const message =
        err instanceof Error
          ? err.message
          : "Gemini AI explanation is currently unavailable. Deterministic finding remains available.";
      setAiErrors((prev) => ({ ...prev, [findingId]: message }));
    } finally {
      setLoadingAI((prev) => ({ ...prev, [findingId]: false }));
    }
  };

  const uniqueRules = useMemo(() => {
    const ruleSet = new Set<string>();
    findings.forEach((f) => ruleSet.add(f.rule_id));
    return Array.from(ruleSet).sort();
  }, [findings]);

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
    <div className="bg-card border border-border rounded-xl p-6 space-y-5">
      {/* Header and Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <h2 className="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-ink-300" />
            <span>Architectural debt findings</span>
            <span className="text-xs px-2 py-0.5 rounded bg-ink-800 border border-border text-ink-400 font-mono">
              {filtered.length} of {findings.length}
            </span>
          </h2>
          <p className="text-xs text-ink-400 mt-0.5">
            Deterministic AST findings across error handling, authentication, input validation, and secrets
          </p>
        </div>

        {/* Filter Toolbar */}
        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Search box */}
          <div className="relative">
            <Search className="h-3.5 w-3.5 text-ink-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search file, rule, symbol"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-ink-850 border border-border rounded-md pl-8 pr-3 py-1.5 text-xs text-white placeholder-ink-500 focus:outline-none focus:border-ink-500 w-44 sm:w-56 font-mono"
            />
          </div>

          {/* Dynamic Rule Filter */}
          <select
            value={selectedRule}
            onChange={(e) => setSelectedRule(e.target.value)}
            className="bg-ink-850 border border-border rounded-md px-2.5 py-1.5 text-xs text-ink-200 focus:outline-none focus:border-ink-500 font-mono cursor-pointer"
          >
            <option value="all">All rules ({uniqueRules.length})</option>
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
            className="bg-ink-850 border border-border rounded-md px-2.5 py-1.5 text-xs text-ink-200 focus:outline-none focus:border-ink-500 capitalize cursor-pointer"
          >
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>

          {/* Expand/Collapse All & Gemini Config */}
          <div className="flex items-center gap-1.5 ml-auto">
            <button
              type="button"
              onClick={() => setShowKeyModal(true)}
              className="flex items-center gap-1.5 text-[11px] text-violet-300 hover:text-white px-2.5 py-1 rounded bg-violet-950/40 border border-violet-700/50 hover:bg-violet-900/50 transition-colors shadow-sm"
              title="Configure Google Gemini API Key for AI Explanation"
            >
              <KeyRound className="h-3 w-3 text-violet-400" />
              <span>Gemini Key</span>
            </button>

            {filtered.length > 0 && (
              <>
                <button
                  type="button"
                  onClick={expandAll}
                  className="text-[11px] text-ink-400 hover:text-white px-2 py-1 rounded bg-ink-800 border border-border transition-colors"
                >
                  Expand all
                </button>
                <button
                  type="button"
                  onClick={collapseAll}
                  className="text-[11px] text-ink-400 hover:text-white px-2 py-1 rounded bg-ink-800 border border-border transition-colors"
                >
                  Collapse all
                </button>
              </>
            )}
          </div>
        </div>

        {/* Gemini API Key Configuration Modal */}
        {showKeyModal && (
          <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
            <div className="bg-ink-900 border border-violet-500/30 rounded-xl p-5 max-w-md w-full shadow-2xl space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-border">
                <div className="flex items-center gap-2">
                  <div className="p-2 rounded-lg bg-violet-500/10 border border-violet-500/20 text-violet-400">
                    <Sparkles className="h-4 w-4" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-white">Google Gemini API Key</h3>
                    <p className="text-[11px] text-ink-400">Used for browser AI explanations</p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setShowKeyModal(false)}
                  className="text-ink-400 hover:text-white p-1 rounded"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="space-y-2 text-xs text-ink-300">
                <label className="block text-ink-200 font-medium">Gemini API Key</label>
                <input
                  type="password"
                  placeholder="AIzaSy..."
                  value={apiKeyInput}
                  onChange={(e) => setApiKeyInput(e.target.value)}
                  className="w-full bg-ink-950 border border-border rounded-lg px-3 py-2 text-xs text-white placeholder-ink-600 focus:outline-none focus:border-violet-500 font-mono"
                />
                <p className="text-[11px] text-ink-400">
                  Key is saved locally in your browser. Get a key from{" "}
                  <a
                    href="https://aistudio.google.com/app/apikey"
                    target="_blank"
                    rel="noreferrer"
                    className="text-violet-400 underline hover:text-violet-300"
                  >
                    Google AI Studio
                  </a>
                  .
                </p>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-border">
                <button
                  type="button"
                  onClick={() => setShowKeyModal(false)}
                  className="px-3 py-1.5 rounded-lg border border-border text-xs text-ink-300 hover:bg-ink-800"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setStoredGeminiApiKey(apiKeyInput);
                    setShowKeyModal(false);
                  }}
                  className="px-4 py-1.5 rounded-lg bg-violet-600 hover:bg-violet-500 text-white text-xs font-medium shadow-md transition-colors"
                >
                  Save Key
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Findings List */}
      <div className="space-y-2">
        {isLoading ? (
          <div className="text-center py-12 text-ink-400 text-xs font-mono">
            Analyzing AST for architectural debt...
          </div>
        ) : findings.length === 0 ? (
          <div className="text-center py-12 px-4 rounded-lg border border-border bg-ink-850">
            <ShieldCheck className="h-8 w-8 text-emerald-400 mx-auto mb-2 opacity-80" />
            <h3 className="text-xs font-medium text-white">Clean architecture</h3>
            <p className="text-xs text-ink-400 mt-0.5 max-w-sm mx-auto">
              No architectural or security debt findings detected by active analyzers
            </p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-10 text-ink-500 text-xs font-mono">
            No findings match your filter criteria
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
                className="border border-border rounded-lg bg-ink-850/60 overflow-hidden transition-colors hover:border-ink-600"
              >
                {/* Header row */}
                <div
                  onClick={() => toggleExpand(finding.id)}
                  className="p-3 flex items-center justify-between gap-3 cursor-pointer select-none"
                >
                  <div className="flex items-start md:items-center gap-2 flex-1 flex-wrap">
                    <span
                      className={`text-[11px] font-medium px-2 py-0.5 rounded border font-mono ${badge.bg} ${badge.text} ${badge.border}`}
                    >
                      {finding.severity}
                    </span>

                    {finding.is_suppressed && (
                      <span className="text-[11px] font-medium px-1.5 py-0.5 rounded border font-mono bg-ink-800 text-ink-300 border-border">
                        Suppressed
                      </span>
                    )}

                    {finding.status === "new" && (
                      <span className="text-[11px] font-medium px-1.5 py-0.5 rounded border font-mono bg-ink-800 text-ink-200 border-border">
                        New
                      </span>
                    )}

                    {finding.status === "resolved" && (
                      <span className="text-[11px] font-medium px-1.5 py-0.5 rounded border font-mono bg-ink-800 text-emerald-400 border-border">
                        Resolved
                      </span>
                    )}

                    <span className="text-[11px] font-mono text-ink-400 bg-ink-800 px-1.5 py-0.5 rounded border border-border">
                      {finding.rule_id}
                    </span>

                    <h3 className="text-xs font-medium text-white tracking-tight">{finding.title}</h3>

                    <div className="flex items-center gap-1.5 text-xs text-ink-400 font-mono">
                      <span className="text-ink-600">•</span>
                      <span className="text-ink-300">
                        {finding.file}:{finding.line_start}-{finding.line_end}
                      </span>
                      {finding.symbol && (
                        <span className="text-ink-300 bg-ink-800 px-1.5 py-0.5 rounded border border-border text-[11px]">
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
                        if (!isExpanded) {
                          setExpandedFindings((prev) => ({ ...prev, [finding.id]: true }));
                        }
                        handleRequestAIExplanation(finding.id);
                      }}
                      className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-violet-600/20 hover:bg-violet-600/30 text-violet-300 hover:text-white font-medium text-[11px] border border-violet-500/30 transition-all shadow-sm"
                      title="Request Gemini AI explanation"
                    >
                      <Sparkles className="h-3 w-3 text-violet-400" />
                      <span>AI Explanation</span>
                    </button>

                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleExpand(finding.id);
                      }}
                      className="p-1 rounded text-ink-400 hover:text-white"
                      aria-label="Toggle details"
                    >
                      {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                    </button>
                  </div>
                </div>

                {/* Expanded details */}
                {isExpanded && (
                  <div className="p-4 pt-2 border-t border-border mt-1 space-y-4 text-xs">
                    {/* Suppression metadata callout */}
                    {finding.is_suppressed && (
                      <div className="bg-ink-800 border border-border rounded-md p-3 text-ink-300">
                        <div className="font-medium text-white flex items-center gap-1.5 mb-1">
                          <ShieldCheck className="h-3.5 w-3.5 text-ink-400" />
                          <span>Suppressed finding ({finding.suppression_source || "manual"})</span>
                        </div>
                        <p className="text-ink-400 text-xs leading-relaxed">
                          {finding.suppression_reason || "This finding is excluded from score and policy evaluations."}
                        </p>
                      </div>
                    )}

                    {/* Description */}
                    <p className="text-ink-300 leading-relaxed">{finding.description}</p>

                    {/* Code Evidence snippet */}
                    {finding.evidence && finding.evidence.content && (
                      <div>
                        <div className="flex items-center gap-1.5 text-ink-400 mb-1 font-mono text-[11px]">
                          <Code className="h-3 w-3 text-ink-400" />
                          <span>
                            Code evidence ({finding.file} lines {finding.evidence.line_start}-{finding.evidence.line_end})
                          </span>
                        </div>
                        <div className="bg-ink-950 rounded-md p-3 border border-border font-mono text-xs overflow-x-auto text-ink-200">
                          <pre>
                            {finding.evidence.content.split("\n").map((line, idx) => {
                              const lineNo = finding.evidence.line_start + idx;
                              const isHighlighted = finding.evidence.highlight_lines.includes(lineNo);
                              return (
                                <div
                                  key={idx}
                                  className={`flex ${
                                    isHighlighted
                                      ? "bg-red-500/10 text-red-300 border-l-2 border-red-400 pl-2"
                                      : "pl-2.5 text-ink-400"
                                  }`}
                                >
                                  <span className="w-8 select-none text-ink-600 text-right pr-3 font-mono text-[11px]">
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
                      <div className="p-3 rounded-md bg-ink-800 border border-border">
                        <div className="flex items-center gap-1.5 font-medium text-white mb-1">
                          <AlertCircle className="h-3.5 w-3.5 text-ink-400" />
                          <span>Debt impact</span>
                        </div>
                        <p className="text-ink-300 leading-relaxed">{finding.impact}</p>
                      </div>

                      <div className="p-3 rounded-md bg-ink-800 border border-border">
                        <div className="flex items-center gap-1.5 font-medium text-white mb-1">
                          <Lightbulb className="h-3.5 w-3.5 text-ink-400" />
                          <span>Recommendation</span>
                        </div>
                        <p className="text-ink-300 leading-relaxed">{finding.recommendation}</p>
                      </div>
                    </div>

                    {/* AI Explanation & Remediation Section */}
                    <div className="pt-2 border-t border-border">
                      {!explanation && !isExplaining && !aiError && (
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2 text-ink-400 text-xs">
                            <Sparkles className="h-3.5 w-3.5 text-violet-400" />
                            <span>Request contextual Google Gemini architectural explanation</span>
                          </div>
                          <button
                            type="button"
                            onClick={() => handleRequestAIExplanation(finding.id)}
                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-violet-600/20 hover:bg-violet-600/30 text-violet-200 hover:text-white font-medium text-xs border border-violet-500/40 transition-colors shadow-sm"
                          >
                            <Sparkles className="h-3.5 w-3.5 text-violet-400" />
                            <span>AI Explanation</span>
                          </button>
                        </div>
                      )}

                      {/* Loading State */}
                      {isExplaining && (
                        <div className="p-4 rounded-md bg-ink-850 border border-violet-500/20 flex items-center justify-center gap-2.5 text-violet-300">
                          <Loader2 className="h-4 w-4 animate-spin text-violet-400" />
                          <span className="font-mono text-xs">
                            Generating Google Gemini AI explanation...
                          </span>
                        </div>
                      )}

                      {/* Error & Inline API Key Configuration */}
                      {aiError && (
                        <div className="p-3.5 rounded-md bg-ink-850 border border-border space-y-2.5 text-ink-300">
                          <div className="flex items-start justify-between gap-3">
                            <div className="flex items-start gap-2">
                              <AlertCircle className="h-4 w-4 text-amber-400 flex-shrink-0 mt-0.5" />
                              <div className="text-xs">
                                <p className="font-medium text-white">
                                  Gemini AI Explanation Unavailable
                                </p>
                                <p className="text-ink-400 text-[11px] mt-0.5">
                                  {aiError.includes("disabled")
                                    ? "AI explanations are disabled in the environment. Set AI_ENABLED=true or provide a Gemini API key below."
                                    : aiError}
                                </p>
                              </div>
                            </div>
                            <button
                              type="button"
                              onClick={() => handleRequestAIExplanation(finding.id)}
                              className="flex items-center gap-1 px-2.5 py-1 rounded bg-ink-700 hover:bg-ink-600 text-white text-[11px] border border-border flex-shrink-0"
                            >
                              <RefreshCw className="h-3 w-3" />
                              <span>Retry</span>
                            </button>
                          </div>

                          {/* Quick inline Gemini API Key entry */}
                          <div className="pt-2 border-t border-border/60 flex items-center gap-2">
                            <input
                              type="password"
                              placeholder="Enter Gemini API key (AIzaSy...)"
                              value={inlineKeyInputs[finding.id] || ""}
                              onChange={(e) =>
                                setInlineKeyInputs((prev) => ({
                                  ...prev,
                                  [finding.id]: e.target.value,
                                }))
                              }
                              className="flex-1 bg-ink-950 border border-border rounded px-2.5 py-1 text-xs text-white placeholder-ink-600 focus:outline-none focus:border-violet-500 font-mono"
                            />
                            <button
                              type="button"
                              onClick={() => {
                                const key = inlineKeyInputs[finding.id];
                                if (key) {
                                  handleRequestAIExplanation(finding.id, key);
                                }
                              }}
                              className="px-3 py-1 rounded bg-violet-600 hover:bg-violet-500 text-white text-xs font-medium transition-colors flex-shrink-0"
                            >
                              Save &amp; Explain
                            </button>
                          </div>
                        </div>
                      )}

                      {/* Structured Gemini Explanation Display */}
                      {explanation && (
                        <div className="p-4 rounded-lg border border-violet-500/30 bg-ink-850 space-y-3">
                          <div className="flex items-center justify-between pb-2 border-b border-border">
                            <div className="flex items-center gap-2">
                              <Sparkles className="h-4 w-4 text-violet-400" />
                              <span className="text-xs font-semibold text-white">
                                AI Explanation (Google Gemini)
                              </span>
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-violet-950/80 text-violet-300 border border-violet-500/30 font-mono">
                                {explanation.model || "gemini-1.5-flash"}
                              </span>
                            </div>
                            <span className="text-[11px] px-1.5 py-0.5 rounded bg-ink-900 text-ink-400 border border-border font-mono">
                              Confidence: {explanation.confidence}
                            </span>
                          </div>

                          <p className="text-xs text-ink-200 leading-relaxed font-medium">
                            {explanation.summary}
                          </p>

                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                            <div className="p-3 rounded-md bg-ink-900 border border-border">
                              <div className="font-medium text-white mb-1">Context</div>
                              <p className="text-ink-400 leading-relaxed">{explanation.why_it_matters}</p>
                            </div>

                            <div className="p-3 rounded-md bg-ink-900 border border-border">
                              <div className="font-medium text-white mb-1">Observable evidence</div>
                              <p className="text-ink-400 leading-relaxed">{explanation.evidence_explanation}</p>
                            </div>
                          </div>

                          <div className="p-3 rounded-md bg-ink-900 border border-border text-xs">
                            <div className="font-medium text-white mb-1">Architectural impact</div>
                            <p className="text-ink-400 leading-relaxed">{explanation.architectural_impact}</p>
                          </div>

                          <div className="p-3 rounded-md bg-ink-900 border border-border text-xs">
                            <div className="font-medium text-white mb-1">Remediation steps</div>
                            <p className="text-ink-300 leading-relaxed">{explanation.remediation}</p>
                          </div>

                          {explanation.suggested_pattern && (
                            <div className="space-y-1">
                              <div className="text-[11px] font-mono text-ink-400">Suggested pattern</div>
                              <div className="bg-ink-950 rounded-md p-3 border border-border font-mono text-xs overflow-x-auto text-emerald-300">
                                <pre>{explanation.suggested_pattern}</pre>
                              </div>
                            </div>
                          )}

                          <div className="flex flex-wrap items-center justify-between text-[11px] font-mono text-ink-500 pt-2 border-t border-border gap-2">
                            <span>
                              Model: {explanation.model} | Prompt v{explanation.prompt_version}
                            </span>
                            <span className="flex items-center gap-1">
                              <Info className="h-3 w-3 text-ink-500" />
                              {explanation.disclaimer}
                            </span>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Deterministic Fingerprint / Audit Footer */}
                    <div className="pt-1 flex items-center justify-between text-[11px] font-mono text-ink-500 border-t border-border">
                      <div className="flex items-center gap-1.5">
                        <Hash className="h-3 w-3 text-ink-500" />
                        <span>ID: {finding.id}</span>
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

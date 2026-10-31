"use client";

import { useState } from "react";
import { AUDIT_PAIRS, InteractiveAuditPair } from "@/lib/examples";
import {
  FileCode,
  Sparkles,
  ArrowRight,
  ChevronLeft,
  ChevronRight,
  Copy,
  Check,
  Shield,
  AlertTriangle,
  Layers,
  Terminal,
  ExternalLink,
} from "lucide-react";
import { EntropyLogo } from "@/components/brand/EntropyLogo";

export function EntropyPairShowcase() {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [copiedCode, setCopiedCode] = useState(false);
  const [copiedReport, setCopiedReport] = useState(false);

  const currentPair: InteractiveAuditPair = AUDIT_PAIRS[currentIndex];

  const handlePrev = () => {
    setCurrentIndex((prev) => (prev > 0 ? prev - 1 : AUDIT_PAIRS.length - 1));
    setCopiedCode(false);
    setCopiedReport(false);
  };

  const handleNext = () => {
    setCurrentIndex((prev) => (prev < AUDIT_PAIRS.length - 1 ? prev + 1 : 0));
    setCopiedCode(false);
    setCopiedReport(false);
  };

  const handleCopyPattern = () => {
    if (!currentPair.explanation.suggested_pattern) return;
    navigator.clipboard.writeText(currentPair.explanation.suggested_pattern);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const handleCopyReport = () => {
    const report = `# Forensic Audit Report: ${currentPair.title}
- Rule: ${currentPair.rule_id}
- File: ${currentPair.fileName}:${currentPair.lineStart}-${currentPair.lineEnd}
- Severity: ${currentPair.severity}

## Executive Summary
${currentPair.explanation.summary}

## Context & Hazard
${currentPair.explanation.why_it_matters}

## Observable AST Evidence
${currentPair.explanation.evidence_explanation}

## Systemic Architectural Impact
${currentPair.explanation.architectural_impact}

## Step-by-Step Remediation
${currentPair.explanation.remediation}

## Suggested Clean Pattern
\`\`\`${currentPair.fileLang}
${currentPair.explanation.suggested_pattern}
\`\`\`

> ${currentPair.explanation.disclaimer}
`;
    navigator.clipboard.writeText(report);
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 2000);
  };

  const codeLines = currentPair.codeSnippet.split("\n");

  return (
    <section className="w-full space-y-4" aria-labelledby="showcase-title">
      {/* Section Header with Navigation */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border/80 pb-3">
        <div className="flex items-center gap-3">
          <div className="p-0.5 rounded-lg border border-border/80 bg-ink-900 shrink-0">
            <EntropyLogo size={24} roundedClassName="rounded-md" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-orange-400 flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-orange-400 animate-pulse" />
                <span>Interactive Forensic Showcase</span>
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-orange-500/10 text-orange-300 border border-orange-500/20">
                AST Evidence &rarr; AI Remediation
              </span>
            </div>
            <h2 id="showcase-title" className="text-sm font-semibold text-white mt-0.5">
              Real AST Findings vs Grounded Explanations
            </h2>
          </div>
        </div>

        {/* Example Switcher Controls */}
        <div className="flex items-center gap-2 self-start sm:self-auto">
          <div className="flex items-center gap-1 bg-ink-950 border border-border rounded-lg p-0.5">
            {AUDIT_PAIRS.map((pair, idx) => (
              <button
                key={pair.id}
                type="button"
                onClick={() => {
                  setCurrentIndex(idx);
                  setCopiedCode(false);
                  setCopiedReport(false);
                }}
                className={`text-[11px] font-mono px-2.5 py-1 rounded transition-colors cursor-pointer ${
                  currentIndex === idx
                    ? "bg-ink-800 text-white font-medium shadow-sm"
                    : "text-ink-400 hover:text-white"
                }`}
              >
                0{idx + 1}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1 bg-ink-950 border border-border rounded-lg p-0.5">
            <button
              type="button"
              onClick={handlePrev}
              aria-label="Previous example"
              className="p-1 text-ink-400 hover:text-white rounded hover:bg-ink-800 transition-colors cursor-pointer"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="text-[11px] font-mono text-ink-400 px-1.5">
              {currentIndex + 1} / {AUDIT_PAIRS.length}
            </span>
            <button
              type="button"
              onClick={handleNext}
              aria-label="Next example"
              className="p-1 text-ink-400 hover:text-white rounded hover:bg-ink-800 transition-colors cursor-pointer"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Side-by-side / Responsive Pair Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-stretch">
        {/* Left Card: Observable Source Code AST Viewport */}
        <div className="lg:col-span-5 rounded-2xl border border-border/90 bg-ink-950/90 overflow-hidden flex flex-col shadow-2xl">
          {/* Editor Titlebar */}
          <div className="px-4 py-2.5 bg-ink-900 border-b border-border/80 flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2">
              <span className="flex items-center gap-1.5" aria-hidden="true">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
              </span>
              <span className="text-ink-400 ml-2">/source</span>
            </div>
            <div className="flex items-center gap-1.5 text-[11px] text-ink-300 bg-ink-850 px-2.5 py-0.5 rounded border border-border/60">
              <FileCode className="w-3 h-3 text-orange-400" />
              <span className="truncate max-w-[200px]">{currentPair.fileName}</span>
            </div>
          </div>

          {/* Code Viewer with Line Numbers */}
          <div className="p-4 flex-1 overflow-x-auto font-mono text-xs leading-relaxed bg-ink-950">
            <div className="min-w-fit">
              {codeLines.map((line, idx) => {
                const lineNum = currentPair.lineStart + idx;
                const isHighlighted = currentPair.highlightLines.includes(lineNum);
                return (
                  <div
                    key={idx}
                    className={`flex items-start gap-3 px-2 py-0.5 rounded ${
                      isHighlighted
                        ? "bg-red-500/15 border-l-2 border-red-500 text-red-200"
                        : "text-ink-300 hover:bg-ink-900/50"
                    }`}
                  >
                    <span className="text-[11px] text-ink-600 select-none w-6 text-right tabular-nums">
                      {lineNum}
                    </span>
                    <pre className="font-mono text-xs overflow-visible">{line}</pre>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Finding Banner Footer */}
          <div className="p-3 bg-red-950/20 border-t border-red-500/30 flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-300 font-mono text-[10px] font-semibold uppercase tracking-wider border border-red-500/30">
                {currentPair.severity}
              </span>
              <span className="font-mono text-ink-300 text-[11px]">
                Rule: {currentPair.rule_id}
              </span>
            </div>
            <span className="text-[11px] text-ink-400 font-mono">
              Category: {currentPair.category}
            </span>
          </div>
        </div>

        {/* Center Connecting Arrow (Desktop only) */}
        <div className="hidden lg:flex lg:col-span-1 flex-col items-center justify-center text-ink-500">
          <div className="h-full w-px bg-gradient-to-b from-transparent via-border to-transparent" />
          <div className="p-2.5 rounded-full bg-ink-900 border border-orange-500/40 text-orange-400 my-2 shadow-lg shadow-orange-500/10">
            <ArrowRight className="w-4 h-4" />
          </div>
          <div className="h-full w-px bg-gradient-to-b from-transparent via-border to-transparent" />
        </div>

        {/* Right Card: Live AI Architectural Explanation & Remediation */}
        <div className="lg:col-span-6 rounded-2xl border border-orange-500/30 bg-ink-950/95 overflow-hidden flex flex-col shadow-2xl space-y-0">
          {/* Explainer Header */}
          <div className="px-4 py-2.5 bg-ink-900/90 border-b border-border/80 flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <Sparkles className="w-3.5 h-3.5 text-orange-400" />
              <span className="font-medium text-white text-xs">
                AI Explanation (Advisory Only)
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                {currentPair.explanation.confidence} confidence
              </span>
            </div>

            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={handleCopyReport}
                className="px-2.5 py-1 bg-ink-800 hover:bg-ink-700 text-ink-300 hover:text-white border border-border rounded text-[11px] font-mono flex items-center gap-1 transition-colors cursor-pointer"
                title="Copy markdown report"
              >
                {copiedReport ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span className="text-emerald-400">Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3 text-ink-400" />
                    <span>Copy Report</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Explanation Content Deck */}
          <div className="p-4 space-y-3.5 flex-1 overflow-y-auto text-xs font-sans">
            {/* Executive Summary */}
            <div className="p-3 rounded-xl bg-ink-900/80 border border-border/80">
              <div className="text-[10px] font-mono font-semibold uppercase tracking-wider text-orange-400 mb-1 flex items-center gap-1.5">
                <Shield className="w-3 h-3" />
                <span>Executive Summary</span>
              </div>
              <p className="text-ink-100 leading-relaxed font-sans text-xs">
                {currentPair.explanation.summary}
              </p>
            </div>

            {/* 2-Column Grid: Context vs Evidence */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <div className="p-2.5 rounded-lg bg-ink-900/60 border border-border/70 space-y-1">
                <div className="text-[10px] font-mono font-semibold uppercase tracking-wider text-amber-400 flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" />
                  <span>Hazard Context</span>
                </div>
                <p className="text-ink-300 text-[11px] leading-relaxed">
                  {currentPair.explanation.why_it_matters}
                </p>
              </div>

              <div className="p-2.5 rounded-lg bg-ink-900/60 border border-border/70 space-y-1">
                <div className="text-[10px] font-mono font-semibold uppercase tracking-wider text-cyan-400 flex items-center gap-1">
                  <FileCode className="w-3 h-3" />
                  <span>AST Evidence</span>
                </div>
                <p className="text-ink-300 text-[11px] leading-relaxed">
                  {currentPair.explanation.evidence_explanation}
                </p>
              </div>
            </div>

            {/* Blast Radius & Architectural Impact */}
            <div className="p-2.5 rounded-lg bg-ink-900/60 border border-border/70 space-y-1">
              <div className="text-[10px] font-mono font-semibold uppercase tracking-wider text-indigo-300 flex items-center gap-1">
                <Layers className="w-3 h-3" />
                <span>Architectural Impact & Blast Radius</span>
              </div>
              <p className="text-ink-300 text-[11px] leading-relaxed font-sans">
                {currentPair.explanation.architectural_impact}
              </p>
            </div>

            {/* Step-by-Step Remediation */}
            <div className="p-2.5 rounded-lg bg-ink-900/60 border border-border/70 space-y-1">
              <div className="text-[10px] font-mono font-semibold uppercase tracking-wider text-emerald-400 flex items-center gap-1">
                <Check className="w-3 h-3" />
                <span>Remediation Strategy</span>
              </div>
              <p className="text-ink-200 text-[11px] leading-relaxed font-sans whitespace-pre-line">
                {currentPair.explanation.remediation}
              </p>
            </div>

            {/* Suggested Idiomatic Pattern */}
            <div className="border border-border rounded-xl overflow-hidden bg-ink-950">
              <div className="px-3 py-1.5 bg-ink-900 border-b border-border flex items-center justify-between">
                <span className="text-[10px] font-mono font-semibold text-emerald-400 flex items-center gap-1.5">
                  <Terminal className="w-3 h-3" />
                  <span>Suggested Pattern (Refactored)</span>
                </span>
                <button
                  type="button"
                  onClick={handleCopyPattern}
                  className="text-[10px] font-mono text-ink-300 hover:text-white px-2 py-0.5 rounded bg-ink-800 border border-border/60 flex items-center gap-1 transition-colors cursor-pointer"
                >
                  {copiedCode ? (
                    <>
                      <Check className="w-2.5 h-2.5 text-emerald-400" />
                      <span className="text-emerald-400">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-2.5 h-2.5 text-ink-400" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>
              <div className="p-3 overflow-x-auto font-mono text-xs text-emerald-300/90 leading-relaxed bg-ink-950">
                <pre>{currentPair.explanation.suggested_pattern}</pre>
              </div>
            </div>
          </div>

          {/* Constitution Disclaimer Footer */}
          <div className="px-4 py-2 bg-ink-900/70 border-t border-border flex flex-wrap items-center justify-between gap-2 text-[10px] font-mono text-ink-500">
            <span>
              Model: {currentPair.explanation.model} &bull; Prompt v{currentPair.explanation.prompt_version}
            </span>
            <span className="text-ink-400 flex items-center gap-1">
              <Shield className="w-3 h-3 text-orange-400" />
              {currentPair.explanation.disclaimer}
            </span>
          </div>
        </div>
      </div>
    </section>
  );
}

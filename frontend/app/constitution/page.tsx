"use client";

import {
  ScrollText,
  CheckCircle2,
  AlertOctagon,
  Scale,
  Shield,
  Sparkles,
  Terminal,
  Cpu,
} from "lucide-react";

export default function ConstitutionPage() {
  const rules = [
    "No mock security findings. Every finding must trace to real AST syntax.",
    "No fake scan results. Empty scans remain empty until actual code is analyzed.",
    "No hardcoded dashboard metrics. Every number originates from actual calculation.",
    "No pretending an analyzer exists when it does not.",
    "Every score must be explainable via step-by-step mathematical audit trails.",
    "Prefer deterministic static analysis over LLM guesses.",
    "AI should explain findings, not invent them.",
    "Fail gracefully when a language cannot be analyzed without terminating execution.",
    "Preserve precise source-code locations and line boundaries.",
    "Make analyzers modular and write unit tests for every analysis rule.",
  ];

  return (
    <div className="max-w-4xl mx-auto space-y-8 pb-12">
      {/* Header */}
      <div className="border-b border-border/80 pb-6">
        <div className="flex items-center gap-2 text-emerald-400 mb-2 font-mono text-xs font-semibold tracking-wider">
          <ScrollText className="h-4 w-4" />
          <span>ENGINEERING CONSTITUTION</span>
          <span className="text-ink-600">•</span>
          <span className="text-ink-400">FOUNDATIONAL COVENANT</span>
        </div>
        <h1 className="text-2xl md:text-3xl font-extrabold text-white tracking-tight">
          The Entropy Engineering Constitution
        </h1>
        <p className="text-xs md:text-sm text-ink-300 mt-2 leading-relaxed">
          Binding principles, architectural covenants, and non-negotiable boundaries governing the
          development, execution, and scoring of the Entropy platform.
        </p>
      </div>

      {/* Article 1: Core Definition */}
      <section className="bg-surface-1 border border-border-subtle rounded-2xl p-6 space-y-3 shadow-xl relative overflow-hidden">
        <div className="flex items-center gap-2.5 text-white font-bold text-sm md:text-base">
          <div className="h-7 w-7 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <Shield className="h-4 w-4" />
          </div>
          <h2>Article I: The Concept of Architectural Security Debt</h2>
        </div>
        <p className="text-xs text-ink-300 leading-relaxed">
          Traditional security scanners primarily focus on acute vulnerabilities that exist today
          (such as SQL injection or known CVEs). Entropy quantifies structural disorder:
        </p>
        <blockquote className="border-l-2 border-emerald-500 pl-4 py-2 text-xs text-emerald-300 italic bg-surface-2 rounded-r">
          &ldquo;Architectural patterns that do not represent an immediate exploit today, but
          accumulate structural disorder, perimeter drift, and compounding maintenance friction
          over time.&rdquo;
        </blockquote>
      </section>

      {/* Article 2: The Non-Attribution Covenant */}
      <section className="bg-surface-1 border border-border-subtle rounded-2xl p-6 space-y-3 shadow-xl relative overflow-hidden">
        <div className="flex items-center gap-2.5 text-white font-bold text-sm md:text-base">
          <div className="h-7 w-7 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
            <AlertOctagon className="h-4 w-4" />
          </div>
          <h2>Article II: The Non-Attribution Covenant (Anti-Hallucination)</h2>
        </div>
        <div className="p-3.5 rounded-xl bg-amber-950/30 border border-amber-900/50 text-xs text-amber-200">
          <strong className="text-white font-semibold">Mandatory Principle:</strong> Entropy must
          NEVER claim &ldquo;This code was written by AI.&rdquo;
        </div>
        <p className="text-xs text-ink-300 leading-relaxed">
          Entropy evaluates verifiable, observable syntactic properties—such as duplicated AST
          subtrees, unmapped routes missing auth guards, and swallowed exceptions—rather than
          hallucinating human vs. AI authorship. The platform provides mathematical audit trails
          grounded in deterministic syntax extraction.
        </p>
      </section>

      {/* Article 3: Separation of Concerns */}
      <section className="bg-surface-1 border border-border-subtle rounded-2xl p-6 space-y-4 shadow-xl">
        <div className="flex items-center gap-2.5 text-white font-bold text-sm md:text-base">
          <div className="h-7 w-7 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400">
            <Scale className="h-4 w-4" />
          </div>
          <h2>Article III: Separation of Concerns &amp; Source of Truth</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          <div className="p-4 bg-surface-2 rounded-xl border border-border-subtle space-y-1">
            <h4 className="font-semibold text-sky-300">Strict Layer Boundaries</h4>
            <p className="text-ink-400 leading-relaxed text-[11px]">
              Ingestion → Parsing → Analysis → Findings → Scoring → AI Explanation → API → Frontend.
              Analysis rules never execute inside UI components.
            </p>
          </div>
          <div className="p-4 bg-surface-2 rounded-xl border border-border-subtle space-y-1">
            <h4 className="font-semibold text-sky-300">Backend Is Source of Truth</h4>
            <p className="text-ink-400 leading-relaxed text-[11px]">
              The frontend is strictly a presentation and visualization tier. It never recalculates,
              overrides, or invents security scores.
            </p>
          </div>
        </div>
      </section>

      {/* Article 4: The 10 Inviolable Rules */}
      <section className="bg-surface-1 border border-border-subtle rounded-2xl p-6 space-y-4 shadow-xl">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5 text-white font-bold text-sm md:text-base">
            <div className="h-7 w-7 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <CheckCircle2 className="h-4 w-4" />
            </div>
            <h2>Article IV: The 10 Inviolable Engineering Rules</h2>
          </div>
          <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/40 px-2.5 py-0.5 rounded border border-emerald-800/60">
            Deterministic Standard
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
          {rules.map((rule, idx) => (
            <div
              key={idx}
              className="flex items-start gap-3 p-3 rounded-xl bg-surface-2 border border-border-subtle text-xs text-ink-300 hover:border-emerald-500/40 transition-colors"
            >
              <span className="text-emerald-400 font-mono font-bold text-xs mt-0.5 shrink-0">
                {(idx + 1).toString().padStart(2, "0")}.
              </span>
              <span className="leading-relaxed">{rule}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

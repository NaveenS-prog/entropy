"use client";

import { ScrollText, CheckCircle2, AlertOctagon, Scale, Shield } from "lucide-react";

export default function ConstitutionPage() {
  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div className="border-b border-border pb-5">
        <div className="flex items-center gap-2 text-ink-400 mb-1.5">
          <ScrollText className="h-4 w-4" />
          <span className="text-xs font-mono text-ink-400">
            Engineering constitution
          </span>
        </div>
        <h1 className="text-xl font-semibold text-white tracking-tight">
          Entropy Engineering Constitution
        </h1>
        <p className="text-xs text-ink-400 mt-1 leading-relaxed">
          Principles, architectural covenants, and system boundaries governing the development and analysis of Entropy
        </p>
      </div>

      {/* Article 1: Core Definition */}
      <section className="bg-card border border-border rounded-xl p-5 space-y-2.5">
        <div className="flex items-center gap-2 text-white font-medium text-sm">
          <Shield className="h-4 w-4 text-ink-400" />
          <h2>Article 1: Concept of architectural security debt</h2>
        </div>
        <p className="text-xs text-ink-300 leading-relaxed">
          Traditional scanners look for acute vulnerabilities in source code today (such as SQL injection or known CVEs). Entropy quantifies structural drift:
        </p>
        <blockquote className="border-l-2 border-border pl-3.5 py-1 text-xs text-ink-200 bg-ink-850 rounded-r">
          Architectural patterns that do not represent an immediate exploit today, but accumulate structural disorder, maintenance friction, and security debt over time.
        </blockquote>
      </section>

      {/* Article 2: The Non-Attribution Covenant */}
      <section className="bg-card border border-border rounded-xl p-5 space-y-2.5">
        <div className="flex items-center gap-2 text-white font-medium text-sm">
          <AlertOctagon className="h-4 w-4 text-ink-400" />
          <h2>Article 2: Non-attribution covenant</h2>
        </div>
        <div className="p-3 rounded-md bg-ink-850 border border-border text-xs text-ink-300">
          <strong className="text-white font-medium">Core rule:</strong> Entropy must never claim &ldquo;This code was written by AI.&rdquo;
        </div>
        <p className="text-xs text-ink-300 leading-relaxed">
          Entropy identifies observable structural patterns, AST inconsistencies, and security divergence. The platform evaluates verifiable syntax properties—such as repeated AST structures, missing validation boundaries, and inconsistent authorization—rather than guessing authorship.
        </p>
      </section>

      {/* Article 3: Separation of Concerns */}
      <section className="bg-card border border-border rounded-xl p-5 space-y-3">
        <div className="flex items-center gap-2 text-white font-medium text-sm">
          <Scale className="h-4 w-4 text-ink-400" />
          <h2>Article 3: Separation of concerns &amp; source of truth</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          <div className="p-3 bg-ink-850 rounded-md border border-border">
            <h4 className="font-medium text-white">Strict layer boundaries</h4>
            <p className="text-ink-400 mt-1 leading-relaxed">
              Ingestion → Parsing → Analysis → Findings → Scoring → AI Explanation → API → Frontend. Static analysis rules never live in UI components.
            </p>
          </div>
          <div className="p-3 bg-ink-850 rounded-md border border-border">
            <h4 className="font-medium text-white">Backend is source of truth</h4>
            <p className="text-ink-400 mt-1 leading-relaxed">
              The frontend is strictly a presentation layer. It never calculates, overrides, or invents scores.
            </p>
          </div>
        </div>
      </section>

      {/* Article 4: The 10 Inviolable Rules */}
      <section className="bg-card border border-border rounded-xl p-5 space-y-3">
        <div className="flex items-center gap-2 text-white font-medium text-sm">
          <CheckCircle2 className="h-4 w-4 text-ink-400" />
          <h2>Article 4: Ten engineering principles</h2>
        </div>
        <ul className="space-y-2 text-xs text-ink-300">
          {[
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
          ].map((rule, idx) => (
            <li key={idx} className="flex items-start gap-2.5">
              <span className="text-ink-500 font-mono text-[11px] mt-0.5">{idx + 1}.</span>
              <span>{rule}</span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

"use client";

import { ScrollText, CheckCircle2, AlertOctagon, Scale, Shield, Terminal } from "lucide-react";

export default function ConstitutionPage() {
  return (
    <div className="max-w-4xl mx-auto space-y-8">
      <div className="border-b border-border pb-6">
        <div className="flex items-center gap-3 text-emerald-400 mb-2">
          <ScrollText className="h-6 w-6" />
          <span className="text-xs uppercase font-mono tracking-widest text-emerald-500">
            ENGINEERING FOUNDATION
          </span>
        </div>
        <h1 className="text-3xl font-extrabold text-white tracking-tight">
          The Entropy Engineering Constitution
        </h1>
        <p className="text-sm text-slate-400 mt-2 leading-relaxed">
          Binding principles, architectural covenants, and product boundaries governing the
          development and operation of Entropy.
        </p>
      </div>

      {/* Article 1: Core Definition */}
      <section className="bg-card border border-border rounded-xl p-6 space-y-3">
        <div className="flex items-center gap-2 text-white font-bold text-base">
          <Shield className="h-5 w-5 text-emerald-400" />
          <h2>Article I: The Concept of Architectural Security Debt</h2>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          Traditional security scanners primarily focus on vulnerabilities that exist in the code{" "}
          <strong className="text-white">TODAY</strong> (e.g. SQL injection, known CVEs).
          Entropy focuses on something different:
        </p>
        <blockquote className="border-l-2 border-emerald-500 pl-4 py-1 text-xs text-emerald-300 italic bg-emerald-950/20 rounded-r">
          &ldquo;Architectural patterns that may not represent an immediate vulnerability today, but
          accumulate security and maintenance risk over time.&rdquo;
        </blockquote>
      </section>

      {/* Article 2: The Non-Attribution Covenant */}
      <section className="bg-card border border-border rounded-xl p-6 space-y-3">
        <div className="flex items-center gap-2 text-white font-bold text-base">
          <AlertOctagon className="h-5 w-5 text-amber-400" />
          <h2>Article II: The Non-Attribution Covenant (Anti-Hallucination)</h2>
        </div>
        <div className="p-3 rounded-lg bg-amber-950/20 border border-amber-900/40 text-xs text-amber-200">
          <strong>Mandatory Principle:</strong> Entropy must NEVER claim &ldquo;This code was
          written by AI.&rdquo;
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          Entropy identifies{" "}
          <em>
            &ldquo;AI-assisted development patterns / generated-code-like structural patterns /
            architectural inconsistencies.&rdquo;
          </em>{" "}
          The product must never present uncertain AI authorship as a fact. The system evaluates
          measurable, observable properties such as structural duplication, repeated AST
          structures, inconsistent security controls, and fragmented error handling.
        </p>
      </section>

      {/* Article 3: Separation of Concerns */}
      <section className="bg-card border border-border rounded-xl p-6 space-y-4">
        <div className="flex items-center gap-2 text-white font-bold text-base">
          <Scale className="h-5 w-5 text-cyan-400" />
          <h2>Article III: Separation of Concerns & Source of Truth</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
            <h4 className="font-semibold text-cyan-400">Strict Layer Boundaries</h4>
            <p className="text-slate-400 mt-1">
              Ingestion → Parsing → Analysis → Findings → Scoring → AI Explanation → API → Frontend.
              Static analysis rules never live in API routes or UI components.
            </p>
          </div>
          <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
            <h4 className="font-semibold text-cyan-400">Backend Is Source of Truth</h4>
            <p className="text-slate-400 mt-1">
              The frontend is strictly a presentation and visualization tier. The frontend NEVER
              calculates or adjusts security scores.
            </p>
          </div>
        </div>
      </section>

      {/* Article 4: The 10 Inviolable Rules */}
      <section className="bg-card border border-border rounded-xl p-6 space-y-4">
        <div className="flex items-center gap-2 text-white font-bold text-base">
          <CheckCircle2 className="h-5 w-5 text-emerald-400" />
          <h2>Article IV: The 10 Inviolable Engineering Rules</h2>
        </div>
        <ul className="space-y-2.5 text-xs text-slate-300">
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
              <span className="text-emerald-400 font-mono font-bold mt-0.5">{idx + 1}.</span>
              <span>{rule}</span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

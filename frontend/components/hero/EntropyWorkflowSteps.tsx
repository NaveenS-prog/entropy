"use client";

import { Shield, Sparkles, FolderGit2, CheckCircle2, ArrowRight, Zap, Lock, Cpu } from "lucide-react";

interface EntropyWorkflowStepsProps {
  onQuickStartSample?: () => void;
}

export function EntropyWorkflowSteps({ onQuickStartSample }: EntropyWorkflowStepsProps) {
  const steps = [
    {
      step: "01",
      tagline: "drop or link.",
      subhead: "Hermetic Ingestion",
      description:
        "Drop a local project directory, upload a .ZIP, or paste a repository URL. Your source code stays in your sandbox — zero external retention.",
      icon: FolderGit2,
      badge: "Local & Private",
      example: "entropy scan ./src",
    },
    {
      step: "02",
      tagline: "deterministic audit.",
      subhead: "Mathematical Scoring",
      description:
        "Entropy parses your Abstract Syntax Tree using immutable static analysis rules. Security hazards, circular imports, and clones are scored deterministically.",
      icon: Shield,
      badge: "0% Hallucination",
      example: "AST Rules ENT-001..ENT-040",
    },
    {
      step: "03",
      tagline: "grounded fix.",
      subhead: "Phase 7 AI Explainer",
      description:
        "The AI analyzes observable AST evidence to provide executive summaries, hazard blast radius, and clean idiomatic code snippets. Strictly advisory.",
      icon: Sparkles,
      badge: "Article II Compliant",
      example: "Refactored Pattern + PR Ready",
    },
  ];

  return (
    <section className="w-full space-y-6 pt-4" aria-labelledby="workflow-steps-heading">
      <div className="text-center max-w-xl mx-auto space-y-2">
        <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-ink-900 border border-border text-[11px] font-mono text-ink-300">
          <Zap className="w-3 h-3 text-orange-400" />
          <span>how it works &bull; 3-step forensic loop</span>
        </div>
        <h2
          id="workflow-steps-heading"
          className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight"
        >
          paste. scan. <span className="font-serif italic font-normal text-orange-400">remediate.</span>
        </h2>
        <p className="text-xs sm:text-sm text-ink-400">
          From raw source files to verified architectural remediation in under five seconds.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {steps.map((s, idx) => {
          const Icon = s.icon;
          return (
            <div
              key={idx}
              className="group relative rounded-2xl border border-border/80 bg-ink-950/60 p-6 flex flex-col justify-between hover:border-orange-500/40 hover:bg-ink-900/40 transition-all duration-300 shadow-lg hover:shadow-orange-500/5"
            >
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-2xl font-mono font-bold text-ink-600 group-hover:text-orange-400 transition-colors">
                    {s.step}
                  </span>
                  <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded-full bg-ink-900 border border-border/70 text-ink-300 group-hover:border-orange-500/30 group-hover:text-orange-300 transition-colors">
                    {s.badge}
                  </span>
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    <div className="h-7 w-7 rounded-lg bg-orange-500/10 border border-orange-500/20 flex items-center justify-center text-orange-400 group-hover:scale-110 transition-transform">
                      <Icon className="w-4 h-4" />
                    </div>
                    <span className="text-xs font-mono uppercase tracking-wider text-ink-400">
                      {s.subhead}
                    </span>
                  </div>
                  <h3 className="text-xl font-bold text-white tracking-tight">
                    {s.tagline}
                  </h3>
                  <p className="text-xs text-ink-300 leading-relaxed pt-1">
                    {s.description}
                  </p>
                </div>
              </div>

              <div className="pt-5 mt-4 border-t border-border/50">
                <div className="flex items-center justify-between text-[11px] font-mono text-ink-400 bg-ink-900/80 px-2.5 py-1.5 rounded border border-border/60">
                  <span className="text-ink-500 truncate max-w-[190px]">{s.example}</span>
                  <ArrowRight className="w-3.5 h-3.5 text-ink-500 group-hover:text-orange-400 group-hover:translate-x-0.5 transition-all" />
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Trust & Guarantees Strip */}
      <div className="rounded-xl border border-border/70 bg-ink-900/40 p-4 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex flex-wrap items-center justify-center sm:justify-start gap-4 text-xs font-mono text-ink-300">
          <div className="flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5 text-emerald-400" />
            <span>Ephemeral sandbox</span>
          </div>
          <span className="text-ink-600 hidden sm:inline">&bull;</span>
          <div className="flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-orange-400" />
            <span>Deterministic AST weights</span>
          </div>
          <span className="text-ink-600 hidden sm:inline">&bull;</span>
          <div className="flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5 text-cyan-400" />
            <span>Article II Rule 8 strictly advisory</span>
          </div>
        </div>

        {onQuickStartSample && (
          <button
            type="button"
            onClick={onQuickStartSample}
            className="text-xs font-mono text-orange-300 hover:text-white inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-orange-500/10 hover:bg-orange-500/20 border border-orange-500/25 transition-all cursor-pointer whitespace-nowrap"
          >
            <CheckCircle2 className="w-3.5 h-3.5 text-orange-400" />
            <span>Try sample fixture now</span>
          </button>
        )}
      </div>
    </section>
  );
}

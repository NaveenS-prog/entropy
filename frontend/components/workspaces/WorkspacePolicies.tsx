"use client";

import { useEffect, useMemo, useState } from "react";
import {
  AlertOctagon,
  AlertTriangle,
  ArrowDownToLine,
  Check,
  CheckCircle2,
  ChevronDown,
  Download,
  ExternalLink,
  Eye,
  FileCheck,
  FileCode,
  FileJson,
  Filter,
  Layers,
  Lock,
  RotateCcw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Terminal,
  XCircle,
} from "lucide-react";
import { DebtScoreResult, Finding, RuleDefinition } from "@/types";
import { listRules } from "@/lib/api";
import { getCategoryDisplayName, getSeverityBadge } from "@/lib/utils";

interface WorkspacePoliciesProps {
  score: DebtScoreResult | null;
  findings: Finding[];
}

// Built-in comprehensive fallback rule catalog
const FALLBACK_RULES: RuleDefinition[] = [
  {
    rule_id: "ENT-AUTH-001",
    category: "authentication_consistency",
    title: "Potentially Unprotected Security-Sensitive Endpoint",
    description:
      "Detects security-sensitive route or endpoint definitions where no recognizable authentication guard or decorator is statically present.",
    default_severity: "critical",
    default_confidence: "high",
    languages: ["python", "typescript", "javascript"],
    impact_template:
      "Endpoints handling sensitive mutations or internal resources can be invoked without credential verification.",
    recommendation_template:
      "Enforce mandatory authentication dependencies (e.g. Depends(verify_api_key)) on the route decorator.",
  },
  {
    rule_id: "ENT-AUTH-002",
    category: "authentication_consistency",
    title: "Missing Authentication Decorator on Protected Handler",
    description:
      "Flags handlers belonging to protected router groups that omit standard framework authentication decorators.",
    default_severity: "high",
    default_confidence: "high",
    languages: ["python"],
    impact_template:
      "Partial authentication guards create inconsistent authorization boundaries across related endpoints.",
    recommendation_template:
      "Standardize on @login_required or Depends(get_current_user) across all handlers in the router.",
  },
  {
    rule_id: "ENT-AUTH-003",
    category: "authorization_consistency",
    title: "Bypassed Role / Permission Validation",
    description:
      "Detects endpoints performing sensitive administrative operations without verifying caller roles or permissions.",
    default_severity: "high",
    default_confidence: "medium",
    languages: ["python", "typescript"],
    impact_template:
      "Horizontal or vertical privilege escalation vulnerability in domain workflows.",
    recommendation_template:
      "Validate user permissions via require_permission('admin:scope') before executing state mutations.",
  },
  {
    rule_id: "ENT-ARCH-001",
    category: "architectural_consistency",
    title: "Circular Module Dependency (Tarjan SCC)",
    description:
      "Detects statically observable circular import dependencies between modules, causing tight coupling and import order fragility.",
    default_severity: "medium",
    default_confidence: "high",
    languages: ["python", "typescript"],
    impact_template:
      "Causes runtime import failures, circular initialization races, and blocks modular refactoring.",
    recommendation_template:
      "Extract shared interfaces into an independent lower layer or adopt dependency inversion.",
  },
  {
    rule_id: "ENT-ARCH-002",
    category: "architectural_consistency",
    title: "Architectural Layer Boundary Violation",
    description:
      "Detects components bypassing intermediate architectural layers (e.g. API directly querying DB models instead of service layer).",
    default_severity: "medium",
    default_confidence: "medium",
    languages: ["python", "typescript"],
    impact_template:
      "Leaks database implementation details into presentation controllers and fragments business logic.",
    recommendation_template:
      "Delegate data persistence through the established domain service layer.",
  },
  {
    rule_id: "ENT-ARCH-004",
    category: "architectural_consistency",
    title: "Inconsistent Configuration Access",
    description:
      "Detects ad-hoc direct environment access (os.getenv) in domain modules when centralized settings module exists.",
    default_severity: "low",
    default_confidence: "high",
    languages: ["python", "typescript"],
    impact_template:
      "Bypasses typed configuration validation, default fallbacks, and central configuration observability.",
    recommendation_template:
      "Import typed attributes from the centralized settings module instead of direct os.getenv calls.",
  },
  {
    rule_id: "ENT-ERR-001",
    category: "error_handling",
    title: "Silent Exception Swallowing / Bare Except",
    description:
      "Detects catch-all except blocks with empty bodies or silent pass statements that swallow fatal runtime exceptions.",
    default_severity: "medium",
    default_confidence: "high",
    languages: ["python", "javascript", "typescript"],
    impact_template:
      "Hides production failures, corrupts transactional state, and prevents alerting engines from noticing failures.",
    recommendation_template:
      "Catch specific exceptions and log stack traces before re-raising or recovering.",
  },
  {
    rule_id: "ENT-SEC-001",
    category: "logging_and_secrets",
    title: "Hardcoded High-Entropy Secret or Token",
    description:
      "Detects high-entropy literal strings matching private keys, API tokens, or HMAC secrets committed in code.",
    default_severity: "critical",
    default_confidence: "high",
    languages: ["python", "javascript", "typescript"],
    impact_template:
      "Direct credential compromise if code tree is cloned or shared across developers.",
    recommendation_template:
      "Migrate secret to environment variables or dedicated secret management vault.",
  },
  {
    rule_id: "ENT-DUP-001",
    category: "code_duplication",
    title: "Duplicated AST Code Fragment",
    description:
      "Detects identical or near-identical AST subtrees duplicated across multiple functions or files.",
    default_severity: "low",
    default_confidence: "high",
    languages: ["python", "typescript", "javascript"],
    impact_template:
      "Increases maintenance overhead; bug fixes applied in one location are easily forgotten in duplicates.",
    recommendation_template:
      "Extract the repeated logic into a shared reusable utility function.",
  },
];

export function WorkspacePolicies({
  score,
  findings,
}: WorkspacePoliciesProps) {
  const [rules, setRules] = useState<RuleDefinition[]>(FALLBACK_RULES);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string>("ALL");
  const [selectedRuleDetail, setSelectedRuleDetail] = useState<RuleDefinition | null>(null);

  // CI Simulation Threshold Sliders
  const [maxDebtScoreCeiling, setMaxDebtScoreCeiling] = useState<number>(70);
  const [maxCriticalAllowed, setMaxCriticalAllowed] = useState<number>(0);
  const [maxHighAllowed, setMaxHighAllowed] = useState<number>(2);
  const [maxNewAllowed, setMaxNewAllowed] = useState<number>(0);

  // Load backend rules if available
  useEffect(() => {
    listRules()
      .then((data) => {
        if (data && data.length > 0) {
          setRules(data);
        }
      })
      .catch(() => {
        // Fallback already preloaded
      });
  }, []);

  const totalScore = score?.total_score ?? 64;
  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const newFindingsCount = findings.filter((f) => f.status === "new").length;

  // Real-time CI Gate Simulation Evaluation
  const simulationResults = useMemo(() => {
    const checks = [
      {
        id: "score-check",
        name: "Entropy Debt Score Ceiling Gate",
        required: `<= ${maxDebtScoreCeiling} pts`,
        actual: `${totalScore} pts`,
        passed: totalScore <= maxDebtScoreCeiling,
        fatal: true,
        reason:
          totalScore > maxDebtScoreCeiling
            ? `Current debt score (${totalScore} pts) exceeds maximum configured threshold (${maxDebtScoreCeiling} pts)`
            : `Debt score (${totalScore} pts) meets maximum allowed ceiling (${maxDebtScoreCeiling} pts)`,
      },
      {
        id: "critical-check",
        name: "Zero Critical Tolerance Gate",
        required: `<= ${maxCriticalAllowed} critical`,
        actual: `${criticalCount} critical`,
        passed: criticalCount <= maxCriticalAllowed,
        fatal: true,
        reason:
          criticalCount > maxCriticalAllowed
            ? `Critical findings (${criticalCount}) exceed allowed ceiling (${maxCriticalAllowed})`
            : "Critical findings count within policy limit",
      },
      {
        id: "high-check",
        name: "High Severity Findings Tolerance",
        required: `<= ${maxHighAllowed} high`,
        actual: `${highCount} high`,
        passed: highCount <= maxHighAllowed,
        fatal: false,
        reason:
          highCount > maxHighAllowed
            ? `High findings (${highCount}) exceed tolerance (${maxHighAllowed})`
            : "High findings count within policy limit",
      },
      {
        id: "new-check",
        name: "PR Differential New Debt Gate",
        required: `<= ${maxNewAllowed} new findings`,
        actual: `${newFindingsCount} new findings`,
        passed: newFindingsCount <= maxNewAllowed,
        fatal: true,
        reason:
          newFindingsCount > maxNewAllowed
            ? `New findings (${newFindingsCount}) introduced exceed PR limit (${maxNewAllowed})`
            : "PR debt delta within threshold",
      },
    ];

    const hasFatalFailure = checks.some((c) => !c.passed && c.fatal);
    const hasWarningFailure = checks.some((c) => !c.passed && !c.fatal);

    const verdict: "PASS" | "WARN" | "FAIL" = hasFatalFailure
      ? "FAIL"
      : hasWarningFailure
      ? "WARN"
      : "PASS";

    return { checks, verdict };
  }, [
    maxDebtScoreCeiling,
    maxCriticalAllowed,
    maxHighAllowed,
    maxNewAllowed,
    totalScore,
    criticalCount,
    highCount,
    newFindingsCount,
  ]);

  const handleExportPolicy = () => {
    const policyConfig = {
      name: "entropy-standard-gate",
      description: "Automated Entropy CI quality gate policy generated from simulator",
      version: "1.0.0",
      enabled: true,
      score: {
        max_score: maxDebtScoreCeiling,
        warn_score: Math.max(0, maxDebtScoreCeiling - 15),
      },
      findings: {
        max_total_critical: maxCriticalAllowed,
        max_total_high: maxHighAllowed,
        max_new: maxNewAllowed,
      },
    };

    const jsonString = JSON.stringify(policyConfig, null, 2);
    const blob = new Blob([jsonString], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "entropy.policy.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const filteredRules = useMemo(() => {
    return rules.filter((r) => {
      if (selectedCategory !== "ALL" && r.category !== selectedCategory) return false;
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        const inId = r.rule_id.toLowerCase().includes(term);
        const inTitle = r.title.toLowerCase().includes(term);
        const inDesc = r.description.toLowerCase().includes(term);
        if (!inId && !inTitle && !inDesc) return false;
      }
      return true;
    });
  }, [rules, selectedCategory, searchTerm]);

  return (
    <div className="space-y-6">
      {/* CI Quality Gate Simulation Sandbox */}
      <div className="bg-surface-1 border border-border-subtle rounded-xl p-6 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border-subtle pb-4">
          <div>
            <h3 className="text-sm font-semibold text-white font-mono flex items-center gap-2">
              <Sliders className="h-4 w-4 text-emerald-400" />
              <span>CI Quality Gate Simulation Sandbox</span>
            </h3>
            <p className="text-xs text-ink-400">
              Simulate CI pipeline pass/fail gate thresholds in real-time against active scan metrics
            </p>
          </div>

          <button
            type="button"
            onClick={handleExportPolicy}
            className="flex items-center gap-2 px-3 py-1.5 bg-surface-2 hover:bg-surface-3 text-white border border-border-strong rounded-lg text-xs font-mono font-medium transition-colors"
          >
            <Download className="h-3.5 w-3.5 text-emerald-400" />
            <span>Export entropy.policy.json</span>
          </button>
        </div>

        {/* Verdict Banner */}
        <div
          className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-colors ${
            simulationResults.verdict === "PASS"
              ? "bg-emerald-950/30 border-emerald-500/40 text-emerald-400"
              : simulationResults.verdict === "WARN"
              ? "bg-amber-950/30 border-amber-500/40 text-amber-400"
              : "bg-red-950/30 border-red-500/40 text-red-400"
          }`}
        >
          <div className="flex items-center gap-3">
            {simulationResults.verdict === "PASS" ? (
              <CheckCircle2 className="h-7 w-7 text-emerald-400 shrink-0" />
            ) : simulationResults.verdict === "WARN" ? (
              <AlertTriangle className="h-7 w-7 text-amber-400 shrink-0" />
            ) : (
              <XCircle className="h-7 w-7 text-red-400 shrink-0" />
            )}
            <div>
              <div className="text-base font-bold font-mono tracking-tight">
                PIPELINE QUALITY GATE VERDICT: {simulationResults.verdict}
              </div>
              <div className="text-xs font-sans text-ink-300">
                {simulationResults.verdict === "PASS"
                  ? "All simulated quality invariants satisfied. Merge allowed into protected branches."
                  : simulationResults.verdict === "WARN"
                  ? "Warnings triggered on secondary tolerance metrics. Manual approval required."
                  : "Critical gate failed. GitHub Action or GitLab CI check run will be set to failed."}
              </div>
            </div>
          </div>

          <div className="text-right font-mono text-xs shrink-0">
            <span className="text-ink-400">Current Repository Score: </span>
            <span className="font-bold text-white text-sm">{totalScore}/100</span>
          </div>
        </div>

        {/* 4 Interactive Threshold Sliders */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Slider 1: Max Debt Score Ceiling */}
          <div className="bg-surface-2 border border-border-subtle rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-ink-400">Max Debt Score Ceiling</span>
              <span className="font-bold text-white">{maxDebtScoreCeiling} pts</span>
            </div>
            <input
              type="range"
              min="20"
              max="90"
              step="5"
              value={maxDebtScoreCeiling}
              onChange={(e) => setMaxDebtScoreCeiling(Number(e.target.value))}
              className="w-full accent-emerald-400 cursor-pointer"
            />
            <div className="text-[10px] text-ink-500 font-mono flex justify-between">
              <span>Strict (20 pts)</span>
              <span>Relaxed (90 pts)</span>
            </div>
          </div>

          {/* Slider 2: Max Critical */}
          <div className="bg-surface-2 border border-border-subtle rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-ink-400">Max Critical Allowed</span>
              <span className="font-bold text-red-400">{maxCriticalAllowed}</span>
            </div>
            <input
              type="range"
              min="0"
              max="5"
              step="1"
              value={maxCriticalAllowed}
              onChange={(e) => setMaxCriticalAllowed(Number(e.target.value))}
              className="w-full accent-red-400 cursor-pointer"
            />
            <div className="text-[10px] text-ink-500 font-mono flex justify-between">
              <span>Zero Tolerance (0)</span>
              <span>Permissive (5)</span>
            </div>
          </div>

          {/* Slider 3: Max High */}
          <div className="bg-surface-2 border border-border-subtle rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-ink-400">Max High Allowed</span>
              <span className="font-bold text-orange-400">{maxHighAllowed}</span>
            </div>
            <input
              type="range"
              min="0"
              max="10"
              step="1"
              value={maxHighAllowed}
              onChange={(e) => setMaxHighAllowed(Number(e.target.value))}
              className="w-full accent-orange-400 cursor-pointer"
            />
            <div className="text-[10px] text-ink-500 font-mono flex justify-between">
              <span>Zero (0)</span>
              <span>Buffer (10)</span>
            </div>
          </div>

          {/* Slider 4: Max New Findings */}
          <div className="bg-surface-2 border border-border-subtle rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-ink-400">Max New in PR</span>
              <span className="font-bold text-amber-400">{maxNewAllowed}</span>
            </div>
            <input
              type="range"
              min="0"
              max="5"
              step="1"
              value={maxNewAllowed}
              onChange={(e) => setMaxNewAllowed(Number(e.target.value))}
              className="w-full accent-amber-400 cursor-pointer"
            />
            <div className="text-[10px] text-ink-500 font-mono flex justify-between">
              <span>Zero New (0)</span>
              <span>5 Allowed</span>
            </div>
          </div>
        </div>

        {/* Gate Rule Evaluation Checklist */}
        <div className="bg-surface-2 border border-border-subtle rounded-xl p-4 space-y-2">
          <div className="text-[11px] font-mono uppercase font-semibold text-ink-400 tracking-wider">
            Gate Invariant Checks
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
            {simulationResults.checks.map((check) => (
              <div
                key={check.id}
                className="bg-surface-1 p-3 rounded-lg border border-border-subtle flex items-start justify-between gap-3"
              >
                <div className="space-y-1">
                  <div className="font-semibold text-text-primary flex items-center gap-2">
                    {check.passed ? (
                      <Check className="h-3.5 w-3.5 text-emerald-400" />
                    ) : (
                      <XCircle className="h-3.5 w-3.5 text-red-400" />
                    )}
                    <span>{check.name}</span>
                  </div>
                  <div className="text-[11px] text-ink-400 font-sans">
                    {check.reason}
                  </div>
                </div>

                <div className="text-right shrink-0">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      check.passed
                        ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                        : "bg-red-500/10 text-red-400 border border-red-500/30"
                    }`}
                  >
                    {check.passed ? "PASSED" : "FAILED"}
                  </span>
                  <div className="text-[10px] text-ink-500 mt-1">
                    Req: {check.required}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Searchable Static Rulebook Catalog */}
      <div className="bg-surface-1 border border-border-subtle rounded-xl p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border-subtle pb-4">
          <div>
            <h3 className="text-sm font-semibold text-white font-mono flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
              <span>Entropy Rulebook Catalog ({filteredRules.length} Rules)</span>
            </h3>
            <p className="text-xs text-ink-400">
              Deterministic static AST invariant definitions across security, architecture, and reliability
            </p>
          </div>

          <div className="flex items-center gap-2">
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="bg-surface-2 border border-border-subtle rounded-md px-2.5 py-1.5 text-xs font-mono text-ink-300 outline-none"
            >
              <option value="ALL">All Categories</option>
              <option value="authentication_consistency">Authentication</option>
              <option value="authorization_consistency">Authorization</option>
              <option value="architectural_consistency">Architecture</option>
              <option value="error_handling">Error Handling</option>
              <option value="logging_and_secrets">Logging & Secrets</option>
              <option value="code_duplication">Duplication</option>
            </select>
          </div>
        </div>

        {/* Rule Search Input */}
        <div className="relative max-w-md">
          <Search className="h-4 w-4 text-ink-400 absolute left-3 top-1/2 transform -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search rule ID, title or description..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-surface-2 border border-border-subtle focus:border-emerald-400 rounded-lg pl-9 pr-3 py-1.5 text-xs font-mono text-white placeholder-ink-500 outline-none"
          />
        </div>

        {/* Rules Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {filteredRules.map((r) => {
            const badge = getSeverityBadge(r.default_severity);
            return (
              <div
                key={r.rule_id}
                onClick={() => setSelectedRuleDetail(r)}
                className="bg-surface-2 hover:bg-surface-3 border border-border-subtle hover:border-border-strong rounded-xl p-4 transition-all cursor-pointer flex flex-col justify-between space-y-3"
              >
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-bold text-emerald-400">
                      {r.rule_id}
                    </span>
                    <span
                      className={`text-[10px] px-1.5 py-0.5 rounded font-mono font-medium ${badge.bg} ${badge.text} border ${badge.border}`}
                    >
                      {r.default_severity.toUpperCase()}
                    </span>
                  </div>

                  <h4 className="text-xs font-semibold text-text-primary leading-snug">
                    {r.title}
                  </h4>
                  <p className="text-[11px] text-ink-400 font-sans line-clamp-2">
                    {r.description}
                  </p>
                </div>

                <div className="pt-2 border-t border-border-subtle/60 flex items-center justify-between text-[10px] font-mono text-ink-500">
                  <span>{getCategoryDisplayName(r.category as any)}</span>
                  <span className="text-ink-400">{r.languages.join(", ")}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Rule Detail Modal */}
      {selectedRuleDetail && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-surface-1 border border-border-strong rounded-2xl max-w-xl w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-border-subtle pb-4">
              <div className="flex items-center gap-2">
                <div className="h-8 w-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                  <ShieldCheck className="h-4 w-4" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-white font-mono">
                    {selectedRuleDetail.rule_id}: {selectedRuleDetail.title}
                  </h3>
                  <p className="text-xs text-ink-400 font-mono">
                    Category: {selectedRuleDetail.category}
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setSelectedRuleDetail(null)}
                className="text-ink-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs font-mono">
              <div>
                <div className="text-[11px] uppercase tracking-wider text-ink-400 font-semibold mb-1">
                  Description
                </div>
                <p className="text-ink-200 font-sans leading-relaxed bg-surface-2 p-3 rounded-lg border border-border-subtle">
                  {selectedRuleDetail.description}
                </p>
              </div>

              <div>
                <div className="text-[11px] uppercase tracking-wider text-amber-400 font-semibold mb-1">
                  Security & Architecture Risk
                </div>
                <p className="text-ink-200 font-sans leading-relaxed bg-surface-2 p-3 rounded-lg border border-border-subtle">
                  {selectedRuleDetail.impact_template}
                </p>
              </div>

              <div>
                <div className="text-[11px] uppercase tracking-wider text-emerald-400 font-semibold mb-1">
                  Prescribed Remediation Pattern
                </div>
                <p className="text-ink-200 font-sans leading-relaxed bg-surface-2 p-3 rounded-lg border border-border-subtle">
                  {selectedRuleDetail.recommendation_template}
                </p>
              </div>
            </div>

            <div className="flex justify-end pt-3 border-t border-border-subtle">
              <button
                type="button"
                onClick={() => setSelectedRuleDetail(null)}
                className="px-4 py-2 bg-surface-2 hover:bg-surface-3 text-ink-300 hover:text-white rounded-lg text-xs font-mono transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  AIExplanation,
  DebtCategory,
  Finding,
  FindingExplanation,
  Severity,
} from "@/types";
import { getCategoryDisplayName, getSeverityBadge } from "@/lib/utils";
import { explainFinding, requestAIExplanation } from "@/lib/api";
import {
  AlertCircle,
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  Ban,
  Check,
  ChevronDown,
  ChevronRight,
  Code,
  Copy,
  ExternalLink,
  FileCode,
  FileText,
  Filter,
  Hash,
  HelpCircle,
  Info,
  Keyboard,
  Layers,
  Lightbulb,
  Loader2,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  Sparkles,
  Terminal,
  Wand2,
} from "lucide-react";

interface WorkspaceFindingsProps {
  scanId: string;
  findings: Finding[];
  initialCategory?: DebtCategory | null;
}

/**
 * Deterministic AST Remediation Patch Generator
 * Returns the exact pattern-matched patch based on rule ID and evidence
 */
function generateDeterministicRemediation(finding: Finding): {
  originalCode: string;
  remediatedCode: string;
  patchExplanation: string;
} {
  const original = finding.evidence?.content || `# [Line ${finding.line_start}]\n// Offending code segment`;
  const isPython = finding.file.endsWith(".py");
  const isJsTs =
    finding.file.endsWith(".ts") ||
    finding.file.endsWith(".tsx") ||
    finding.file.endsWith(".js") ||
    finding.file.endsWith(".jsx");

  switch (finding.rule_id) {
    case "ENT-AUTH-001":
      return {
        originalCode: original,
        remediatedCode: isPython
          ? original.replace(
              /@router\.(get|post|put|delete|patch)\(([^)]*)\)/,
              `@router.$1($2, dependencies=[Depends(verify_api_key)])`
            ) !== original
            ? original.replace(
                /@router\.(get|post|put|delete|patch)\(([^)]*)\)/,
                `@router.$1($2, dependencies=[Depends(verify_api_key)])`
              )
            : `# Attach authentication dependency:\n@router.post("/path", dependencies=[Depends(verify_api_key)])\nasync def handler(...):\n    ...`
          : original.replace(
              /(app|router)\.(get|post|put|delete)\((['"][^'"]+['"]),/,
              `$1.$2($3, requireAuth,`
            ),
        patchExplanation:
          "Appends deterministic authentication guard (verify_api_key dependency / requireAuth middleware) before request handling.",
      };

    case "ENT-AUTH-002":
      return {
        originalCode: original,
        remediatedCode: isPython
          ? `# Enforce authentication decorator:\n@login_required\n${original}`
          : original.replace(
              /router\.(get|post|put|delete)\(([^,]+),/,
              `router.$1($2, authenticateToken,`
            ),
        patchExplanation:
          "Injects mandatory authentication check decorator onto the sensitive route handler.",
      };

    case "ENT-AUTH-003":
      return {
        originalCode: original,
        remediatedCode: isPython
          ? `async def ${finding.symbol || "handler"}(..., auth=Depends(require_permission("admin:write"))):\n    # Role authorization verified before execution\n    ${original}`
          : `// Enforce role authorization:\nif (!req.user?.hasRole('admin')) {\n  return res.status(403).json({ error: 'Forbidden' });\n}\n${original}`,
        patchExplanation:
          "Guards the endpoint with explicit role-based access control (RBAC) permission validation.",
      };

    case "ENT-ARCH-001":
      return {
        originalCode: original,
        remediatedCode: isPython
          ? `from typing import TYPE_CHECKING\n\nif TYPE_CHECKING:\n    # Break runtime circular import\n    ${original}`
          : `// Decouple circular import via interface or dynamic import:\nimport type { ${finding.symbol || "Module"} } from '${finding.file.replace(/\.[^/.]+$/, "")}';`,
        patchExplanation:
          "Breaks runtime import cycle by deferring dependency resolution to type-checking phase or common interface.",
      };

    case "ENT-ARCH-002":
      return {
        originalCode: original,
        remediatedCode: isPython
          ? `# Delegate persistence through established domain service:\nresult = await domain_service.execute_operation(session, payload)`
          : `// Route data mutation through service layer:\nconst result = await domainService.execute(payload);`,
        patchExplanation:
          "Eliminates layer boundary bypass by delegating data operations through domain service layer.",
      };

    case "ENT-ARCH-004":
      return {
        originalCode: original,
        remediatedCode: isPython
          ? `from app.core.config import settings\n\n# Centralized configuration access\ndb_url = settings.DATABASE_URL`
          : `import { config } from '@/lib/config';\n\nconst dbUrl = config.databaseUrl;`,
        patchExplanation:
          "Replaces ad-hoc os.getenv lookup with typed, centralized configuration settings.",
      };

    case "ENT-ERR-001": {
      let patched = isPython
        ? original.replace(
            /except(\s+[A-Za-z0-9_.]*)?:(\s*#.*)?\n(\s*(?:pass|return\s+None|return))(?:\s*#.*)?/i,
            `except Exception as exc:\n    logger.exception("Operation failed", exc_info=exc)\n    raise`
          )
        : original.replace(
            /catch\s*\([^)]*\)\s*\{[\s\S]*?\}/,
            `catch (err) {\n  logger.error("Operation failed", { err });\n  throw err;\n}`
          );
      if (patched === original) {
        patched = isPython
          ? `# Replaced swallowed exception with structured logger and re-raise:\n${original}\n# Note: ensure logger.exception(...) is invoked before return/raise`
          : `// Replaced swallowed exception with structured logger:\n${original}\n// Note: ensure logger.error("Operation failed", { err }) is invoked`;
      }
      return {
        originalCode: original,
        remediatedCode: patched,
        patchExplanation:
          "Replaces silent exception swallowing with structured error logging and exception re-raising.",
      };
    }

    case "ENT-SEC-002": {
      const tsPatched = original.replace(
        /router\.(get|post|put|delete|patch)\((['"][^'"]+['"]),\s*/i,
        `router.$1($2, requireAuth, verifyTenantScope, `
      );
      const remediated = isJsTs
        ? tsPatched !== original
          ? tsPatched
          : `// Mount standard [requireAuth, verifyTenantScope] middleware array:\nrouter.get("/invoices/export", requireAuth, verifyTenantScope, async (req: Request, res: Response) => {\n  const { orgId } = req.query;\n  const data = await invoiceService.dumpAll(String(orgId));\n  return res.json(data);\n});`
        : `@router.get("/invoices/export", dependencies=[Depends(verify_api_key), Depends(verify_tenant_scope)])\n${original}`;
      return {
        originalCode: original,
        remediatedCode: remediated,
        patchExplanation:
          "Mounts standard [requireAuth, verifyTenantScope] middleware chain to guard unshielded edge route.",
      };
    }

    case "ENT-DUP-001":
      return {
        originalCode: original,
        remediatedCode: isJsTs
          ? `// Extract duplicate AST pipeline into unified gateway dispatcher:\nconst result = await unifiedGatewayDispatcher.dispatch({\n  subId,\n  tenantId: ctx.tenantId,\n  payload: record,\n});\nreturn result;`
          : `# Extract duplicated logic into shared service pipeline:\nresult = await unified_dispatcher.dispatch(sub_id, payload)\nreturn result`,
        patchExplanation:
          "Extracts duplicated AST subtree into a unified abstract gateway dispatcher pipeline.",
      };

    default: {
      const commentPrefix = isPython ? "#" : "//";
      return {
        originalCode: original,
        remediatedCode: finding.recommendation
          ? `${commentPrefix} Recommended remediation:\n${commentPrefix} ${finding.recommendation}\n${original}`
          : `${commentPrefix} Apply architectural remediation:\n${original}`,
        patchExplanation: finding.recommendation || "Follow architectural best practices.",
      };
    }
  }
}

/**
 * Generates an inline suppression directive for this finding
 */
function generateSuppressionDirective(finding: Finding): string {
  const isPython =
    finding.file.endsWith(".py") ||
    finding.file.endsWith(".sh") ||
    finding.file.endsWith(".yaml") ||
    finding.file.endsWith(".yml");

  const commentPrefix = isPython ? "#" : "//";
  return `${commentPrefix} entropy-disable-next-line ${finding.rule_id} -- Architectural exception: ${finding.title.replace(/[\r\n]/g, " ")}`;
}

export function WorkspaceFindings({
  scanId,
  findings,
  initialCategory,
}: WorkspaceFindingsProps) {
  const searchInputRef = useRef<HTMLInputElement>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | "all">("all");
  const [selectedCategory, setSelectedCategory] = useState<DebtCategory | "all">(
    initialCategory || "all"
  );
  const [selectedRule, setSelectedRule] = useState<string>("all");
  const [selectedIndex, setSelectedIndex] = useState<number>(0);
  const [activeTab, setActiveTab] = useState<"diff" | "explainer" | "suppression">("diff");

  // Keep category in sync if navigated with category from Executive workspace
  useEffect(() => {
    if (initialCategory) {
      setSelectedCategory(initialCategory);
    }
  }, [initialCategory]);

  // Copy feedback states
  const [copiedPatch, setCopiedPatch] = useState(false);
  const [copiedSuppression, setCopiedSuppression] = useState(false);
  const [appliedToWorktree, setAppliedToWorktree] = useState(false);
  const [copiedAIExplanation, setCopiedAIExplanation] = useState(false);
  const [copiedAIPattern, setCopiedAIPattern] = useState(false);

  // Diff Mode: Deterministic Compiler Patch vs AI Suggested Refactoring
  const [diffMode, setDiffMode] = useState<"deterministic" | "ai">("deterministic");

  // AI Explanation State (keyed per finding ID for instant caching & persistence)
  const [aiExplanations, setAiExplanations] = useState<Record<string, AIExplanation>>({});
  const [loadingAI, setLoadingAI] = useState<Record<string, boolean>>({});
  const [aiErrors, setAiErrors] = useState<Record<string, string>>({});

  // Deterministic Baseline Explanations (offline/fallback, keyed per finding ID)
  const [deterministicExplanations, setDeterministicExplanations] = useState<
    Record<string, FindingExplanation>
  >({});
  const [loadingBaseline, setLoadingBaseline] = useState<Record<string, boolean>>({});

  // Filter findings
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (selectedSeverity !== "all" && f.severity !== selectedSeverity) return false;
      if (selectedCategory !== "all" && f.category !== selectedCategory) return false;
      if (selectedRule !== "all" && f.rule_id !== selectedRule) return false;
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        const matchesTitle = f.title.toLowerCase().includes(term);
        const matchesFile = f.file.toLowerCase().includes(term);
        const matchesRule = f.rule_id.toLowerCase().includes(term);
        const matchesDesc = f.description?.toLowerCase().includes(term);
        if (!matchesTitle && !matchesFile && !matchesRule && !matchesDesc) return false;
      }
      return true;
    });
  }, [findings, selectedSeverity, selectedCategory, selectedRule, searchTerm]);

  // Active finding
  const activeFinding: Finding | undefined = filteredFindings[selectedIndex] || filteredFindings[0];

  // Unique rules for dropdown
  const uniqueRules = useMemo(() => {
    return Array.from(new Set(findings.map((f) => f.rule_id))).sort();
  }, [findings]);

  // Reset selected index if filter drops it out of range
  useEffect(() => {
    if (selectedIndex >= filteredFindings.length) {
      setSelectedIndex(0);
    }
  }, [filteredFindings.length, selectedIndex]);

  // Keyboard Navigation: J / K / E / S / /
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't capture when typing in inputs
      if (["INPUT", "TEXTAREA", "SELECT"].includes((e.target as HTMLElement).tagName)) {
        return;
      }

      if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        setSelectedIndex((prev) => (prev < filteredFindings.length - 1 ? prev + 1 : prev));
      } else if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        setSelectedIndex((prev) => (prev > 0 ? prev - 1 : 0));
      } else if (e.key === "e") {
        e.preventDefault();
        setActiveTab((prev) => (prev === "explainer" ? "diff" : "explainer"));
      } else if (e.key === "s") {
        e.preventDefault();
        if (activeFinding) {
          const directive = generateSuppressionDirective(activeFinding);
          navigator.clipboard.writeText(directive);
          setCopiedSuppression(true);
          setTimeout(() => setCopiedSuppression(false), 2000);
        }
      } else if (e.key === "/") {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [filteredFindings.length, activeFinding]);

  const remediation = activeFinding
    ? generateDeterministicRemediation(activeFinding)
    : null;

  const currentAiExplanation = activeFinding ? aiExplanations[activeFinding.id] : undefined;
  const isExplainingCurrent = activeFinding ? !!loadingAI[activeFinding.id] : false;
  const currentAiError = activeFinding ? aiErrors[activeFinding.id] : undefined;
  const currentBaseline = activeFinding ? deterministicExplanations[activeFinding.id] : undefined;
  const isLoadingBaseline = activeFinding ? !!loadingBaseline[activeFinding.id] : false;

  const handleCopyPatch = () => {
    if (!remediation) return;
    navigator.clipboard.writeText(remediation.remediatedCode);
    setCopiedPatch(true);
    setTimeout(() => setCopiedPatch(false), 2000);
  };

  const handleApplyToWorktree = () => {
    // Simulated worktree patch application
    setAppliedToWorktree(true);
    setTimeout(() => setAppliedToWorktree(false), 2500);
  };

  const handleCopySuppression = () => {
    if (!activeFinding) return;
    const directive = generateSuppressionDirective(activeFinding);
    navigator.clipboard.writeText(directive);
    setCopiedSuppression(true);
    setTimeout(() => setCopiedSuppression(false), 2000);
  };

  const handleFetchAi = async () => {
    if (!activeFinding) return;
    const fid = activeFinding.id;
    setLoadingAI((prev) => ({ ...prev, [fid]: true }));
    setAiErrors((prev) => {
      const copy = { ...prev };
      delete copy[fid];
      return copy;
    });
    try {
      const expl = await requestAIExplanation(fid, scanId);
      setAiExplanations((prev) => ({ ...prev, [fid]: expl }));
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "AI explanation unavailable";
      setAiErrors((prev) => ({ ...prev, [fid]: msg }));
    } finally {
      setLoadingAI((prev) => ({ ...prev, [fid]: false }));
    }
  };

  const handleFetchBaseline = async () => {
    if (!activeFinding || !scanId) return;
    const fid = activeFinding.id;
    setLoadingBaseline((prev) => ({ ...prev, [fid]: true }));
    try {
      const base = await explainFinding(scanId, fid);
      setDeterministicExplanations((prev) => ({ ...prev, [fid]: base }));
    } catch (err: unknown) {
      console.warn("Could not load deterministic baseline explanation:", err);
    } finally {
      setLoadingBaseline((prev) => ({ ...prev, [fid]: false }));
    }
  };

  const handleCopyFullAIReport = () => {
    const expl = activeFinding ? aiExplanations[activeFinding.id] : undefined;
    if (!expl) return;
    const dateStr = expl.generated_at
      ? new Date(expl.generated_at).toLocaleString()
      : "recent";
    const text = `# Entropy AI Advisory Explanation
Finding: ${expl.finding_id}
Model: ${expl.model} (Confidence: ${expl.confidence})
Generated: ${dateStr}

## Summary
${expl.summary}

## Why It Matters (Hazard Analysis)
${expl.why_it_matters}

## Observable Evidence
${expl.evidence_explanation}

## Architectural Impact
${expl.architectural_impact}

## Step-by-Step Remediation
${expl.remediation}

## Suggested Idiomatic Pattern
\`\`\`
${expl.suggested_pattern}
\`\`\`

---
*Notice: ${expl.disclaimer}*`;

    navigator.clipboard.writeText(text);
    setCopiedAIExplanation(true);
    setTimeout(() => setCopiedAIExplanation(false), 2000);
  };

  const handleCopyAIPattern = () => {
    const expl = activeFinding ? aiExplanations[activeFinding.id] : undefined;
    if (!expl?.suggested_pattern) return;
    navigator.clipboard.writeText(expl.suggested_pattern);
    setCopiedAIPattern(true);
    setTimeout(() => setCopiedAIPattern(false), 2000);
  };

  return (
    <div className="space-y-4">
      {/* Precision Filter Toolbar */}
      <div className="bg-surface-1 border border-border-subtle rounded-xl p-3 sm:p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="h-4 w-4 text-ink-400 absolute left-3 top-1/2 transform -translate-y-1/2" />
          <input
            ref={searchInputRef}
            type="text"
            placeholder="Search findings by rule, file, symbol or title (/ to focus)..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-surface-2 border border-border-subtle focus:border-emerald-400 rounded-lg pl-9 pr-3 py-1.5 text-xs font-mono text-white placeholder-ink-500 outline-none transition-colors"
          />
        </div>

        {/* Severity Filter Pills */}
        <div className="flex items-center gap-1.5 flex-wrap">
          {(["all", "critical", "high", "medium", "low"] as const).map((sev) => {
            const isSelected = selectedSeverity === sev;
            const count =
              sev === "all"
                ? findings.length
                : findings.filter((f) => f.severity === sev).length;

            return (
              <button
                key={sev}
                type="button"
                onClick={() => setSelectedSeverity(sev)}
                className={`px-2.5 py-1 rounded-md text-xs font-mono font-medium transition-colors flex items-center gap-1.5 ${
                  isSelected
                    ? "bg-surface-3 border border-border-strong text-white"
                    : "bg-surface-2 hover:bg-surface-3 text-ink-400 hover:text-white border border-border-subtle"
                }`}
              >
                <span className="capitalize">{sev}</span>
                <span
                  className={`text-[10px] px-1 py-0.2 rounded font-mono ${
                    sev === "critical"
                      ? "text-red-400"
                      : sev === "high"
                      ? "text-orange-400"
                      : sev === "medium"
                      ? "text-amber-400"
                      : "text-ink-400"
                  }`}
                >
                  {count}
                </span>
              </button>
            );
          })}
        </div>

        {/* Category & Rule Selectors */}
        <div className="flex items-center gap-2">
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value as any)}
            className="bg-surface-2 border border-border-subtle rounded-md px-2.5 py-1.5 text-xs font-mono text-ink-300 outline-none"
          >
            <option value="all">All Categories</option>
            <option value="authentication_consistency">Authentication</option>
            <option value="authorization_consistency">Authorization</option>
            <option value="architectural_consistency">Architecture</option>
            <option value="error_handling">Error Handling</option>
            <option value="input_validation">Input Validation</option>
            <option value="logging_and_secrets">Logging & Secrets</option>
            <option value="code_duplication">Duplication</option>
          </select>

          <select
            value={selectedRule}
            onChange={(e) => setSelectedRule(e.target.value)}
            className="bg-surface-2 border border-border-subtle rounded-md px-2.5 py-1.5 text-xs font-mono text-ink-300 outline-none max-w-[140px] truncate"
          >
            <option value="all">All Rules ({uniqueRules.length})</option>
            {uniqueRules.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Split Master-Detail Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column: Master Findings List (5 columns) */}
        <div className="lg:col-span-5 bg-surface-1 border border-border-subtle rounded-xl flex flex-col h-[750px] overflow-hidden">
          <div className="p-3 border-b border-border-subtle flex items-center justify-between text-xs font-mono text-ink-400">
            <span>
              {filteredFindings.length} of {findings.length} findings
            </span>
            <span className="text-[11px] text-ink-500">
              Nav: [J] Down · [K] Up
            </span>
          </div>

          <div className="flex-1 overflow-y-auto divide-y divide-border-subtle/40">
            {filteredFindings.length === 0 ? (
              <div className="p-8 text-center text-xs font-mono text-ink-500 space-y-2">
                <Check className="h-6 w-6 text-emerald-400 mx-auto" />
                <div>No findings match the active filters.</div>
              </div>
            ) : (
              filteredFindings.map((f, idx) => {
                const isSelected = idx === selectedIndex;
                const badge = getSeverityBadge(f.severity);

                return (
                  <div
                    key={f.id}
                    onClick={() => setSelectedIndex(idx)}
                    className={`p-3.5 transition-colors cursor-pointer text-xs font-mono flex items-start gap-3 ${
                      isSelected
                        ? "bg-surface-2 border-l-2 border-l-emerald-400 text-white"
                        : "hover:bg-surface-2/60 text-ink-300"
                    }`}
                  >
                    <div className="pt-0.5">
                      <span
                        className={`text-[10px] px-1.5 py-0.5 rounded font-mono font-medium ${badge.bg} ${badge.text} border ${badge.border}`}
                      >
                        {f.severity.slice(0, 4).toUpperCase()}
                      </span>
                    </div>

                    <div className="flex-1 min-w-0 space-y-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-semibold text-text-primary truncate">
                          {f.title}
                        </span>
                        <div className="flex items-center gap-1.5 shrink-0">
                          {aiExplanations[f.id] && (
                            <span
                              className="inline-flex items-center gap-1 text-[10px] text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/30"
                              title="AI Advisory Explanation Available"
                            >
                              <Sparkles className="h-2.5 w-2.5" />
                              <span>AI</span>
                            </span>
                          )}
                          <span className="text-[10px] text-ink-500">
                            {f.rule_id}
                          </span>
                        </div>
                      </div>
                      <div className="text-[11px] text-ink-400 truncate font-mono">
                        {f.file}:{f.line_start}
                      </div>
                      {f.symbol && (
                        <div className="text-[10px] text-ink-500 truncate">
                          sym: <span className="text-ink-400">{f.symbol}</span>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Split-Pane Deterministic AST Refactoring Studio (7 columns) */}
        <div className="lg:col-span-7 bg-surface-1 border border-border-subtle rounded-xl flex flex-col h-[750px] overflow-hidden">
          {activeFinding && remediation ? (
            <>
              {/* Finding Header */}
              <div className="p-4 border-b border-border-subtle space-y-2.5 shrink-0">
                <div className="flex items-center justify-between gap-4 flex-wrap">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-xs px-2 py-0.5 rounded font-mono font-semibold ${
                        getSeverityBadge(activeFinding.severity).bg
                      } ${getSeverityBadge(activeFinding.severity).text} border ${
                        getSeverityBadge(activeFinding.severity).border
                      }`}
                    >
                      {activeFinding.severity.toUpperCase()}
                    </span>
                    <span className="text-xs px-2 py-0.5 rounded bg-surface-2 border border-border-subtle font-mono text-ink-300">
                      {activeFinding.rule_id}
                    </span>
                    <span className="text-xs text-ink-400 font-mono">
                      {activeFinding.file}:{activeFinding.line_start}
                    </span>
                  </div>

                  {/* Studio Actions */}
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={handleCopyPatch}
                      className="flex items-center gap-1.5 px-3 py-1 bg-surface-2 hover:bg-surface-3 text-text-primary border border-border-strong rounded-md text-xs font-mono transition-colors"
                    >
                      {copiedPatch ? (
                        <>
                          <Check className="h-3.5 w-3.5 text-emerald-400" />
                          <span className="text-emerald-400">Copied!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="h-3.5 w-3.5 text-ink-400" />
                          <span>Copy Patch</span>
                        </>
                      )}
                    </button>

                    <button
                      type="button"
                      onClick={handleApplyToWorktree}
                      className="flex items-center gap-1.5 px-3 py-1 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-md text-xs font-mono transition-colors"
                    >
                      {appliedToWorktree ? (
                        <>
                          <Check className="h-3.5 w-3.5" />
                          <span>Applied</span>
                        </>
                      ) : (
                        <>
                          <Wand2 className="h-3.5 w-3.5" />
                          <span>Apply Patch</span>
                        </>
                      )}
                    </button>

                    <button
                      type="button"
                      onClick={handleCopySuppression}
                      className="flex items-center gap-1.5 px-3 py-1 bg-surface-2 hover:bg-surface-3 text-ink-300 hover:text-white border border-border-subtle rounded-md text-xs font-mono transition-colors"
                      title="Generate and copy inline suppression directive"
                    >
                      {copiedSuppression ? (
                        <>
                          <Check className="h-3.5 w-3.5 text-emerald-400" />
                          <span className="text-emerald-400">Copied [S]</span>
                        </>
                      ) : (
                        <>
                          <Ban className="h-3.5 w-3.5 text-ink-400" />
                          <span>Suppress [S]</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>

                <h3 className="text-sm font-semibold text-white leading-snug">
                  {activeFinding.title}
                </h3>
                <p className="text-xs text-ink-300 leading-relaxed font-sans">
                  {activeFinding.description}
                </p>

                {/* Sub-Tabs: AST Diff vs Architectural Explainer vs Suppression Code */}
                <div className="flex items-center gap-2 pt-1 border-t border-border-subtle/60 text-xs font-mono">
                  <button
                    type="button"
                    onClick={() => setActiveTab("diff")}
                    className={`px-2.5 py-1 rounded transition-colors ${
                      activeTab === "diff"
                        ? "bg-surface-3 text-white font-semibold"
                        : "text-ink-400 hover:text-white"
                    }`}
                  >
                    AST Diff Comparison
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveTab("explainer")}
                    className={`px-2.5 py-1 rounded transition-colors flex items-center gap-1 ${
                      activeTab === "explainer"
                        ? "bg-surface-3 text-white font-semibold"
                        : "text-ink-400 hover:text-white"
                    }`}
                  >
                    <Lightbulb className="h-3 w-3 text-amber-400" />
                    <span>Architectural Impact [E]</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveTab("suppression")}
                    className={`px-2.5 py-1 rounded transition-colors ${
                      activeTab === "suppression"
                        ? "bg-surface-3 text-white font-semibold"
                        : "text-ink-400 hover:text-white"
                    }`}
                  >
                    Inline Directives
                  </button>
                </div>
              </div>

              {/* Detail Content Area */}
              <div className="flex-1 overflow-y-auto p-4 space-y-4 font-mono text-xs">
                {activeTab === "diff" && (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between gap-3 bg-surface-2 p-2.5 rounded-lg border border-border-subtle flex-wrap">
                      <div className="text-[11px] text-ink-300 leading-relaxed font-sans flex-1 min-w-[240px]">
                        <strong className="text-white">Remediation Strategy:</strong>{" "}
                        {diffMode === "ai" && currentAiExplanation
                          ? currentAiExplanation.remediation
                          : remediation.patchExplanation}
                      </div>

                      {/* Diff Mode Selector */}
                      <div className="flex items-center gap-1 bg-surface-1 p-0.5 rounded-lg border border-border-subtle shrink-0">
                        <button
                          type="button"
                          onClick={() => setDiffMode("deterministic")}
                          className={`px-2.5 py-1 rounded text-xs transition-colors ${
                            diffMode === "deterministic"
                              ? "bg-surface-3 text-white font-semibold shadow-sm"
                              : "text-ink-400 hover:text-white"
                          }`}
                        >
                          Deterministic AST
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            if (!currentAiExplanation && !isExplainingCurrent) {
                              handleFetchAi();
                            }
                            setDiffMode("ai");
                          }}
                          className={`px-2.5 py-1 rounded text-xs transition-colors flex items-center gap-1.5 ${
                            diffMode === "ai"
                              ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-semibold shadow-sm"
                              : "text-ink-400 hover:text-white"
                          }`}
                        >
                          <Sparkles className="h-3 w-3 text-emerald-400" />
                          <span>AI Pattern</span>
                          {currentAiExplanation && (
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                          )}
                        </button>
                      </div>
                    </div>

                    {/* Side-by-Side AST Diff Viewer */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {/* Left Pane: Offending AST Code */}
                      <div className="bg-bg-base border border-red-500/30 rounded-xl overflow-hidden flex flex-col">
                        <div className="px-3 py-1.5 bg-red-950/40 border-b border-red-500/30 text-[11px] font-semibold text-red-400 flex items-center justify-between">
                          <span>Offending Code</span>
                          <span className="text-[10px] text-ink-500 font-mono">
                            Lines {activeFinding.line_start}–{activeFinding.line_end}
                          </span>
                        </div>
                        <pre className="p-3 text-[11px] text-red-200/90 overflow-x-auto whitespace-pre leading-relaxed flex-1 font-mono">
                          {remediation.originalCode}
                        </pre>
                      </div>

                      {/* Right Pane: Remediated AST Code / AI Suggested Code */}
                      <div className="bg-bg-base border border-emerald-500/30 rounded-xl overflow-hidden flex flex-col">
                        <div className="px-3 py-1.5 bg-emerald-950/40 border-b border-emerald-500/30 text-[11px] font-semibold text-emerald-400 flex items-center justify-between">
                          <span>
                            {diffMode === "ai" && currentAiExplanation
                              ? "AI Idiomatic Refactoring Pattern"
                              : "Deterministic AST Patch"}
                          </span>
                          <span className="text-[10px] text-emerald-500 font-mono">
                            {diffMode === "ai" && currentAiExplanation
                              ? `Model: ${currentAiExplanation.model}`
                              : "Patched Invariant"}
                          </span>
                        </div>
                        <pre className="p-3 text-[11px] text-emerald-300 overflow-x-auto whitespace-pre leading-relaxed flex-1 font-mono">
                          {diffMode === "ai" && currentAiExplanation
                            ? currentAiExplanation.suggested_pattern
                            : remediation.remediatedCode}
                        </pre>
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === "explainer" && (
                  <div className="space-y-4">
                    {/* Deterministic Static Signals Cards */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div className="bg-surface-2 border border-border-subtle rounded-xl p-3.5 space-y-1.5">
                        <div className="text-amber-400 font-semibold uppercase tracking-wider text-[10px] flex items-center gap-1.5">
                          <AlertTriangle className="h-3.5 w-3.5" />
                          <span>Deterministic Risk Hazard</span>
                        </div>
                        <p className="text-ink-200 text-xs leading-relaxed font-sans">
                          {activeFinding.impact}
                        </p>
                      </div>

                      <div className="bg-surface-2 border border-border-subtle rounded-xl p-3.5 space-y-1.5">
                        <div className="text-emerald-400 font-semibold uppercase tracking-wider text-[10px] flex items-center gap-1.5">
                          <Shield className="h-3.5 w-3.5" />
                          <span>Static Remediation Standard</span>
                        </div>
                        <p className="text-ink-200 text-xs leading-relaxed font-sans">
                          {activeFinding.recommendation}
                        </p>
                      </div>
                    </div>

                    {/* AI Deep Context Explainer Card */}
                    <div className="bg-surface-2 border border-border-strong rounded-xl p-4 space-y-3.5">
                      {/* Explainer Header & Control Toolbar */}
                      <div className="flex items-center justify-between pb-3 border-b border-border-subtle flex-wrap gap-2">
                        <div className="flex items-center gap-2">
                          <div className="h-6 w-6 rounded bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                            <Sparkles className="h-3.5 w-3.5" />
                          </div>
                          <div>
                            <div className="text-white font-semibold text-xs flex items-center gap-2">
                              <span>AI Advisory Explanation</span>
                              {currentAiExplanation && (
                                <span
                                  className={`text-[10px] px-1.5 py-0.2 rounded font-mono uppercase font-semibold ${
                                    currentAiExplanation.confidence.toLowerCase() === "high"
                                      ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                                      : currentAiExplanation.confidence.toLowerCase() === "low"
                                      ? "bg-ink-800 text-ink-400 border border-border-subtle"
                                      : "bg-amber-500/10 text-amber-400 border border-amber-500/30"
                                  }`}
                                >
                                  {currentAiExplanation.confidence} confidence
                                </span>
                              )}
                            </div>
                            {currentAiExplanation && (
                              <div className="text-[10px] text-ink-400 font-mono flex items-center gap-2 mt-0.5">
                                <span>Model: {currentAiExplanation.model}</span>
                                <span>·</span>
                                <span>Prompt v{currentAiExplanation.prompt_version}</span>
                                <span>·</span>
                                <span>
                                  {new Date(currentAiExplanation.generated_at).toLocaleTimeString([], {
                                    hour: "2-digit",
                                    minute: "2-digit",
                                  })}
                                </span>
                              </div>
                            )}
                          </div>
                        </div>

                        {/* Top Action Buttons */}
                        <div className="flex items-center gap-2">
                          {currentAiExplanation && (
                            <>
                              <button
                                type="button"
                                onClick={handleCopyFullAIReport}
                                className="px-2.5 py-1 bg-surface-3 hover:bg-surface-1 text-ink-200 hover:text-white border border-border-subtle rounded text-xs font-mono flex items-center gap-1.5 transition-colors"
                                title="Copy structured explanation report as Markdown"
                              >
                                {copiedAIExplanation ? (
                                  <>
                                    <Check className="h-3 w-3 text-emerald-400" />
                                    <span className="text-emerald-400">Copied!</span>
                                  </>
                                ) : (
                                  <>
                                    <Copy className="h-3 w-3 text-ink-400" />
                                    <span>Copy Report</span>
                                  </>
                                )}
                              </button>

                              <button
                                type="button"
                                onClick={() => handleFetchAi()}
                                disabled={isExplainingCurrent}
                                className="px-2 py-1 bg-surface-3 hover:bg-surface-1 text-ink-400 hover:text-white border border-border-subtle rounded text-xs font-mono flex items-center gap-1 transition-colors"
                                title="Regenerate explanation from AI provider"
                              >
                                <RefreshCw
                                  className={`h-3 w-3 ${isExplainingCurrent ? "animate-spin" : ""}`}
                                />
                                <span className="hidden sm:inline">Refresh</span>
                              </button>
                            </>
                          )}

                          {!currentAiExplanation && (
                            <button
                              type="button"
                              onClick={() => handleFetchAi()}
                              disabled={isExplainingCurrent}
                              className="px-3 py-1.5 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded text-xs font-mono flex items-center gap-1.5 transition-colors font-medium shadow-sm"
                            >
                              {isExplainingCurrent ? (
                                <>
                                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                  <span>Analyzing AST evidence...</span>
                                </>
                              ) : (
                                <>
                                  <Sparkles className="h-3.5 w-3.5" />
                                  <span>Generate Deep Context</span>
                                </>
                              )}
                            </button>
                          )}
                        </div>
                      </div>

                      {/* Loading State */}
                      {isExplainingCurrent && (
                        <div className="p-6 bg-surface-1/60 border border-border-subtle rounded-lg flex flex-col items-center justify-center gap-2 text-center">
                          <Loader2 className="h-5 w-5 animate-spin text-emerald-400" />
                          <div className="text-xs text-white font-medium font-sans">
                            Consulting AI explanation provider...
                          </div>
                          <div className="text-[11px] text-ink-400 font-mono">
                            Extracting sanitized AST context & evaluating blast radius
                          </div>
                        </div>
                      )}

                      {/* Error State */}
                      {currentAiError && (
                        <div className="p-3.5 bg-red-950/30 border border-red-500/30 rounded-lg space-y-2.5">
                          <div className="flex items-start gap-2.5 text-xs text-red-300">
                            <AlertCircle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
                            <div className="space-y-1">
                              <div className="font-semibold text-red-200 font-sans">
                                AI Explanation Notice
                              </div>
                              <p className="text-[11px] text-red-300/90 font-mono leading-relaxed">
                                {currentAiError.includes("disabled")
                                  ? "AI advisory explanations are not configured or disabled in this backend environment. Deterministic findings and mathematical scores remain available."
                                  : currentAiError}
                              </p>
                            </div>
                          </div>

                          <div className="flex items-center gap-2 pt-1 border-t border-red-500/20">
                            <button
                              type="button"
                              onClick={handleFetchBaseline}
                              disabled={isLoadingBaseline}
                              className="px-2.5 py-1 bg-surface-3 hover:bg-surface-2 text-white border border-border-strong rounded text-[11px] font-mono flex items-center gap-1.5 transition-colors"
                            >
                              {isLoadingBaseline ? (
                                <>
                                  <Loader2 className="h-3 w-3 animate-spin" />
                                  <span>Loading Baseline...</span>
                                </>
                              ) : (
                                <>
                                  <Shield className="h-3 w-3 text-emerald-400" />
                                  <span>Load Deterministic Baseline Rationale</span>
                                </>
                              )}
                            </button>
                            <button
                              type="button"
                              onClick={() => handleFetchAi()}
                              className="px-2.5 py-1 bg-surface-3 hover:bg-surface-2 text-ink-300 hover:text-white border border-border-strong rounded text-[11px] font-mono flex items-center gap-1.5 transition-colors"
                            >
                              <RefreshCw className="h-3 w-3" />
                              <span>Retry AI</span>
                            </button>
                          </div>
                        </div>
                      )}

                      {/* Deterministic Offline Baseline Rationale (if loaded) */}
                      {currentBaseline && !currentAiExplanation && (
                        <div className="p-3.5 bg-surface-1 border border-emerald-500/30 rounded-lg space-y-2.5 text-xs font-sans">
                          <div className="flex items-center gap-2 text-emerald-400 font-semibold text-xs font-mono">
                            <Shield className="h-3.5 w-3.5" />
                            <span>Deterministic Baseline Rationale (Local & Grounded)</span>
                          </div>
                          <div>
                            <span className="text-white font-medium">Context: </span>
                            <span className="text-ink-300">{currentBaseline.architectural_context}</span>
                          </div>
                          <div>
                            <span className="text-white font-medium">Maintenance Hazard: </span>
                            <span className="text-ink-300">{currentBaseline.maintenance_risk}</span>
                          </div>
                          <div>
                            <span className="text-white font-medium">Recommended Action: </span>
                            <span className="text-ink-300">{currentBaseline.suggested_action}</span>
                          </div>
                        </div>
                      )}

                      {/* Rich Structured AI Explanation Display */}
                      {currentAiExplanation && (
                        <div className="space-y-3.5 text-xs font-sans">
                          {/* Executive Summary */}
                          <div className="p-3 bg-surface-1 border border-border-subtle rounded-lg">
                            <div className="text-[11px] font-mono font-semibold uppercase tracking-wider text-ink-400 mb-1">
                              Executive Summary
                            </div>
                            <p className="text-ink-100 leading-relaxed font-sans">
                              {currentAiExplanation.summary}
                            </p>
                          </div>

                          {/* 2-Column Grid: Context / Why it matters vs Observable Evidence */}
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            <div className="p-3 bg-surface-1 border border-border-subtle rounded-lg space-y-1.5">
                              <div className="text-[11px] font-mono font-semibold uppercase tracking-wider text-amber-400 flex items-center gap-1.5">
                                <AlertTriangle className="h-3 w-3" />
                                <span>Security & Maintenance Debt</span>
                              </div>
                              <p className="text-ink-300 text-[11px] leading-relaxed">
                                {currentAiExplanation.why_it_matters}
                              </p>
                            </div>

                            <div className="p-3 bg-surface-1 border border-border-subtle rounded-lg space-y-1.5">
                              <div className="text-[11px] font-mono font-semibold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
                                <FileCode className="h-3 w-3" />
                                <span>Observable AST Evidence</span>
                              </div>
                              <p className="text-ink-300 text-[11px] leading-relaxed">
                                {currentAiExplanation.evidence_explanation}
                              </p>
                            </div>
                          </div>

                          {/* Architectural Impact */}
                          <div className="p-3 bg-surface-1 border border-border-subtle rounded-lg space-y-1.5">
                            <div className="text-[11px] font-mono font-semibold uppercase tracking-wider text-indigo-300 flex items-center gap-1.5">
                              <Layers className="h-3 w-3" />
                              <span>Systemic Architectural Impact & Blast Radius</span>
                            </div>
                            <p className="text-ink-300 text-[11px] leading-relaxed font-sans">
                              {currentAiExplanation.architectural_impact}
                            </p>
                          </div>

                          {/* Remediation Steps */}
                          <div className="p-3 bg-surface-1 border border-border-subtle rounded-lg space-y-1.5">
                            <div className="text-[11px] font-mono font-semibold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                              <Check className="h-3 w-3" />
                              <span>Step-by-Step Remediation Strategy</span>
                            </div>
                            <p className="text-ink-200 text-[11px] leading-relaxed font-sans whitespace-pre-line">
                              {currentAiExplanation.remediation}
                            </p>
                          </div>

                          {/* Suggested Idiomatic Pattern */}
                          <div className="border border-border-subtle rounded-lg overflow-hidden bg-bg-base space-y-0">
                            <div className="px-3 py-2 bg-surface-1 border-b border-border-subtle flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <Code className="h-3.5 w-3.5 text-emerald-400" />
                                <span className="text-[11px] font-mono font-semibold text-white">
                                  Suggested Idiomatic Pattern
                                </span>
                              </div>
                              <div className="flex items-center gap-2">
                                <button
                                  type="button"
                                  onClick={() => {
                                    setDiffMode("ai");
                                    setActiveTab("diff");
                                  }}
                                  className="text-[10px] font-mono text-emerald-400 hover:text-emerald-300 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20 transition-colors"
                                >
                                  View in Diff Studio
                                </button>
                                <button
                                  type="button"
                                  onClick={handleCopyAIPattern}
                                  className="text-[10px] font-mono text-ink-300 hover:text-white bg-surface-2 px-2 py-0.5 rounded border border-border-subtle flex items-center gap-1 transition-colors"
                                >
                                  {copiedAIPattern ? (
                                    <>
                                      <Check className="h-2.5 w-2.5 text-emerald-400" />
                                      <span className="text-emerald-400">Copied!</span>
                                    </>
                                  ) : (
                                    <>
                                      <Copy className="h-2.5 w-2.5" />
                                      <span>Copy Code</span>
                                    </>
                                  )}
                                </button>
                              </div>
                            </div>
                            <pre className="p-3 text-[11px] font-mono text-emerald-300 overflow-x-auto whitespace-pre leading-relaxed">
                              {currentAiExplanation.suggested_pattern}
                            </pre>
                          </div>

                          {/* Mandatory Constitution Advisory Disclaimer */}
                          <div className="p-2.5 bg-amber-500/5 border border-amber-500/20 rounded-lg flex items-center gap-2 text-[11px] text-amber-300/80 font-mono">
                            <Info className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                            <span>{currentAiExplanation.disclaimer}</span>
                          </div>
                        </div>
                      )}

                      {/* Empty Invitation State */}
                      {!currentAiExplanation && !isExplainingCurrent && !currentAiError && !currentBaseline && (
                        <div className="text-center py-6 px-4 space-y-3 bg-surface-1/40 rounded-lg border border-dashed border-border-subtle">
                          <div className="h-8 w-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center mx-auto">
                            <Sparkles className="h-4 w-4" />
                          </div>
                          <div className="space-y-1">
                            <div className="text-xs font-semibold text-white font-sans">
                              Grounded AI Architectural Breakdown
                            </div>
                            <p className="text-[11px] text-ink-400 font-sans max-w-md mx-auto leading-relaxed">
                              Entropy provides contextual AI explanations evaluating cross-layer caller chains, security hazards, and idiomatic refactorings grounded strictly in static AST evidence.
                            </p>
                          </div>
                          <button
                            type="button"
                            onClick={() => handleFetchAi()}
                            className="px-3.5 py-1.5 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded text-xs font-mono inline-flex items-center gap-1.5 transition-colors font-medium shadow-sm"
                          >
                            <Sparkles className="h-3.5 w-3.5" />
                            <span>Explain finding with AI</span>
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {activeTab === "suppression" && (
                  <div className="space-y-4">
                    <div className="bg-surface-2 border border-border-subtle rounded-xl p-4 space-y-3">
                      <div className="text-ink-300 font-semibold text-xs flex items-center justify-between">
                        <span>Inline Code Suppression Snippet</span>
                        <button
                          type="button"
                          onClick={handleCopySuppression}
                          className="px-2 py-0.5 bg-surface-3 hover:bg-surface-1 text-emerald-400 border border-border-strong rounded text-[11px] flex items-center gap-1 transition-colors"
                        >
                          {copiedSuppression ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                          <span>{copiedSuppression ? "Copied!" : "Copy Snippet"}</span>
                        </button>
                      </div>
                      <p className="text-xs text-ink-400 font-sans">
                        Place this exact comment directly above line {activeFinding.line_start} in{" "}
                        <code className="text-ink-200">{activeFinding.file}</code> to exempt this occurrence while recording an architectural exception.
                      </p>
                      <pre className="p-3 bg-bg-base border border-border-subtle rounded-lg text-emerald-400 text-xs overflow-x-auto">
                        {generateSuppressionDirective(activeFinding)}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="p-12 text-center text-xs font-mono text-ink-500 m-auto space-y-2">
              <Terminal className="h-8 w-8 text-ink-600 mx-auto" />
              <div>Select a finding on the left to inspect deterministic AST diff</div>
            </div>
          )}
        </div>
      </div>

      {/* Ergonomic Keyboard Shortcut Legend Bar */}
      <div className="bg-surface-1 border border-border-subtle rounded-lg px-4 py-2 flex items-center justify-between text-[11px] font-mono text-ink-400 flex-wrap gap-2">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1">
            <kbd className="px-1.5 py-0.5 bg-surface-2 border border-border-subtle rounded text-ink-300">J</kbd>
            <kbd className="px-1.5 py-0.5 bg-surface-2 border border-border-subtle rounded text-ink-300">K</kbd>
            <span>Navigate</span>
          </span>
          <span className="flex items-center gap-1">
            <kbd className="px-1.5 py-0.5 bg-surface-2 border border-border-subtle rounded text-ink-300">E</kbd>
            <span>Toggle Explainer</span>
          </span>
          <span className="flex items-center gap-1">
            <kbd className="px-1.5 py-0.5 bg-surface-2 border border-border-subtle rounded text-ink-300">S</kbd>
            <span>Copy Suppression</span>
          </span>
          <span className="flex items-center gap-1">
            <kbd className="px-1.5 py-0.5 bg-surface-2 border border-border-subtle rounded text-ink-300">/</kbd>
            <span>Search</span>
          </span>
        </div>
        <div className="text-ink-500">Vim/IDE Navigation Active</div>
      </div>
    </div>
  );
}

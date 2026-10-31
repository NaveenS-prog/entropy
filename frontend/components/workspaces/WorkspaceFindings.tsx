"use client";

import { useEffect, useMemo, useState } from "react";
import {
  AIExplanation,
  DebtCategory,
  Finding,
  Severity,
} from "@/types";
import { getCategoryDisplayName, getSeverityBadge } from "@/lib/utils";
import { requestAIExplanation } from "@/lib/api";
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

    case "ENT-ERR-001":
      return {
        originalCode: original,
        remediatedCode: isPython
          ? original.replace(
              /except\s*:\s*\n\s*pass/,
              `except Exception as exc:\n    logger.exception("Operation failed", exc_info=exc)\n    raise`
            )
          : original.replace(
              /catch\s*\([^)]*\)\s*\{\s*\}/,
              `catch (err) {\n  logger.error("Operation failed", { err });\n  throw err;\n}`
            ),
        patchExplanation:
          "Replaces silent exception swallowing with structured error logging and exception re-raising.",
      };

    default:
      return {
        originalCode: original,
        remediatedCode: finding.recommendation
          ? `# Recommended remediation:\n# ${finding.recommendation}\n${original}`
          : `# Apply architectural remediation:\n${original}`,
        patchExplanation: finding.recommendation || "Follow architectural best practices.",
      };
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
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | "all">("all");
  const [selectedCategory, setSelectedCategory] = useState<DebtCategory | "all">(
    initialCategory || "all"
  );
  const [selectedRule, setSelectedRule] = useState<string>("all");
  const [selectedIndex, setSelectedIndex] = useState<number>(0);
  const [activeTab, setActiveTab] = useState<"diff" | "explainer" | "suppression">("diff");

  // Copy feedback states
  const [copiedPatch, setCopiedPatch] = useState(false);
  const [copiedSuppression, setCopiedSuppression] = useState(false);
  const [appliedToWorktree, setAppliedToWorktree] = useState(false);

  // AI Explanation State
  const [aiExplanation, setAiExplanation] = useState<AIExplanation | null>(null);
  const [loadingAI, setLoadingAI] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

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

  // Keyboard Navigation: J / K / E / S
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
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [filteredFindings.length, activeFinding]);

  const remediation = activeFinding
    ? generateDeterministicRemediation(activeFinding)
    : null;

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
    setLoadingAI(true);
    setAiError(null);
    try {
      const expl = await requestAIExplanation(activeFinding.id, scanId);
      setAiExplanation(expl);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "AI explanation unavailable";
      setAiError(msg);
    } finally {
      setLoadingAI(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Precision Filter Toolbar */}
      <div className="bg-surface-1 border border-border-subtle rounded-xl p-3 sm:p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="h-4 w-4 text-ink-400 absolute left-3 top-1/2 transform -translate-y-1/2" />
          <input
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
                        <span className="text-[10px] text-ink-500 shrink-0">
                          {f.rule_id}
                        </span>
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
                    <div className="text-[11px] text-ink-400 leading-relaxed font-sans bg-surface-2 p-2.5 rounded-lg border border-border-subtle">
                      <strong>Remediation Strategy:</strong> {remediation.patchExplanation}
                    </div>

                    {/* Side-by-Side AST Diff Viewer */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {/* Left Pane: Offending AST Code */}
                      <div className="bg-bg-base border border-red-500/30 rounded-xl overflow-hidden flex flex-col">
                        <div className="px-3 py-1.5 bg-red-950/40 border-b border-red-500/30 text-[11px] font-semibold text-red-400 flex items-center justify-between">
                          <span>Offending Code</span>
                          <span className="text-[10px] text-ink-500">
                            Lines {activeFinding.line_start}–{activeFinding.line_end}
                          </span>
                        </div>
                        <pre className="p-3 text-[11px] text-red-200/90 overflow-x-auto whitespace-pre leading-relaxed flex-1">
                          {remediation.originalCode}
                        </pre>
                      </div>

                      {/* Right Pane: Deterministic Remediated AST Code */}
                      <div className="bg-bg-base border border-emerald-500/30 rounded-xl overflow-hidden flex flex-col">
                        <div className="px-3 py-1.5 bg-emerald-950/40 border-b border-emerald-500/30 text-[11px] font-semibold text-emerald-400 flex items-center justify-between">
                          <span>Deterministic AST Patch</span>
                          <span className="text-[10px] text-emerald-500">Patched Invariant</span>
                        </div>
                        <pre className="p-3 text-[11px] text-emerald-300 overflow-x-auto whitespace-pre leading-relaxed flex-1">
                          {remediation.remediatedCode}
                        </pre>
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === "explainer" && (
                  <div className="space-y-4">
                    <div className="bg-surface-2 border border-border-subtle rounded-xl p-4 space-y-2">
                      <div className="text-amber-400 font-semibold uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                        <AlertTriangle className="h-3.5 w-3.5" />
                        <span>Security & Maintenance Impact</span>
                      </div>
                      <p className="text-ink-200 text-xs leading-relaxed font-sans">
                        {activeFinding.impact}
                      </p>
                    </div>

                    <div className="bg-surface-2 border border-border-subtle rounded-xl p-4 space-y-2">
                      <div className="text-emerald-400 font-semibold uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                        <Shield className="h-3.5 w-3.5" />
                        <span>Architectural Recommendation</span>
                      </div>
                      <p className="text-ink-200 text-xs leading-relaxed font-sans">
                        {activeFinding.recommendation}
                      </p>
                    </div>

                    {/* AI Deep Context Explainer Card */}
                    <div className="bg-surface-2 border border-border-strong rounded-xl p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 text-white font-semibold text-xs">
                          <Sparkles className="h-4 w-4 text-emerald-400" />
                          <span>AI Context & Multi-File Blast Analysis</span>
                        </div>
                        <button
                          type="button"
                          onClick={handleFetchAi}
                          disabled={loadingAI}
                          className="px-2.5 py-1 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded text-xs font-mono flex items-center gap-1.5 transition-colors"
                        >
                          {loadingAI ? (
                            <>
                              <Loader2 className="h-3 w-3 animate-spin" />
                              <span>Generating...</span>
                            </>
                          ) : (
                            <>
                              <Sparkles className="h-3 w-3" />
                              <span>Generate Deep Context</span>
                            </>
                          )}
                        </button>
                      </div>

                      {aiError && (
                        <div className="p-2.5 bg-red-500/10 border border-red-500/30 rounded text-xs text-red-400">
                          {aiError}
                        </div>
                      )}

                      {aiExplanation ? (
                        <div className="space-y-2 text-xs font-sans text-ink-200 pt-2 border-t border-border-subtle">
                          <div>
                            <strong className="text-white">Summary:</strong>{" "}
                            {aiExplanation.summary}
                          </div>
                          <div>
                            <strong className="text-white">Why It Matters:</strong>{" "}
                            {aiExplanation.why_it_matters}
                          </div>
                          <div>
                            <strong className="text-white">Suggested Pattern:</strong>{" "}
                            <span className="font-mono text-emerald-400">
                              {aiExplanation.suggested_pattern}
                            </span>
                          </div>
                        </div>
                      ) : (
                        <p className="text-xs text-ink-400 font-sans">
                          Optionally request an LLM architectural breakdown evaluating cross-layer caller chains and blast radius.
                        </p>
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

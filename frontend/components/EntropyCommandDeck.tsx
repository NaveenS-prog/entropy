"use client";

import { useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  Boxes,
  Check,
  ChevronDown,
  Code2,
  Copy,
  ExternalLink,
  FileCode,
  FileJson,
  FolderGit2,
  GitBranch,
  GitCommit,
  GitFork,
  GitPullRequest,
  Globe,
  Loader2,
  Play,
  RotateCcw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Sparkles,
  Terminal,
} from "lucide-react";
import {
  DebtCategory,
  DebtScoreResult,
  Finding,
  RepositoryManifest,
  RepositoryScanResult,
  SystemHealth,
} from "@/types";
import { downloadSarifFile } from "@/lib/sarif";

export type WorkspaceId =
  | "executive"
  | "findings"
  | "architecture"
  | "routes"
  | "pr_delta"
  | "policies";

interface EntropyCommandDeckProps {
  activeWorkspace: WorkspaceId;
  onSelectWorkspace: (id: WorkspaceId) => void;
  scans: RepositoryScanResult[];
  activeScan: RepositoryScanResult | null;
  onSelectScan: (scanId: string) => void;
  findings: Finding[];
  score: DebtScoreResult | null;
  manifest: RepositoryManifest | null;
  health: SystemHealth | null;
  isScanning: boolean;
  onTriggerScan: (repoPath: string, repoName?: string) => Promise<void>;
}

export function EntropyCommandDeck({
  activeWorkspace,
  onSelectWorkspace,
  scans,
  activeScan,
  onSelectScan,
  findings,
  score,
  manifest,
  health,
  isScanning,
  onTriggerScan,
}: EntropyCommandDeckProps) {
  const [showScanModal, setShowScanModal] = useState(false);
  const [newScanPath, setNewScanPath] = useState("");
  const [newScanName, setNewScanName] = useState("");
  const [scanModalError, setScanModalError] = useState<string | null>(null);
  const [copiedPrComment, setCopiedPrComment] = useState(false);
  const [isSelectorOpen, setIsSelectorOpen] = useState(false);
  const [isExportMenuOpen, setIsExportMenuOpen] = useState(false);

  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const cycleCount = findings.filter((f) => f.rule_id === "ENT-ARCH-001").length;
  const missingGuardCount = findings.filter(
    (f) =>
      f.rule_id === "ENT-AUTH-001" ||
      f.rule_id === "ENT-AUTH-002" ||
      f.rule_id === "ENT-AUTH-003"
  ).length;

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newScanPath.trim()) return;
    setScanModalError(null);
    try {
      await onTriggerScan(newScanPath.trim(), newScanName.trim() || undefined);
      setShowScanModal(false);
      setNewScanPath("");
      setNewScanName("");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to run scan";
      setScanModalError(msg);
    }
  };

  const handleExportSarif = () => {
    if (!activeScan) return;
    downloadSarifFile(activeScan, findings, score);
    setIsExportMenuOpen(false);
  };

  const handleExportJson = () => {
    if (!activeScan) return;
    const exportData = {
      scan: activeScan,
      score,
      manifest,
      findings,
      exportedAt: new Date().toISOString(),
    };
    const jsonString = JSON.stringify(exportData, null, 2);
    const blob = new Blob([jsonString], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `entropy-manifest-${activeScan.scan_id.slice(0, 8)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setIsExportMenuOpen(false);
  };

  const handleCopyPrComment = () => {
    const repoName = activeScan?.repository?.name || activeScan?.repo_name || "Repository";
    const totalScore = score?.total_score ?? "N/A";
    const tier = score?.tier?.toUpperCase().replace("_", " ") ?? "EVALUATING";
    const totalFindings = findings.length;

    const prComment = `## 🛡️ Entropy Security & Architectural Debt Report
**Target Repository:** \`${repoName}\`  
**Calibrated Debt Score:** \`${totalScore}/100\` (${tier})  
**Evaluated Findings:** \`${totalFindings}\` (${criticalCount} Critical, ${highCount} High)  
${score?.severity_floor_applied ? `> ⚠️ **Severity Floor Alert:** ${score.floor_reason}\n` : ""}
| Category | Score | Findings | Status |
|:---|:---:|:---:|:---:|
${Object.entries(score?.category_scores || {})
  .map(
    ([cat, val]) =>
      `| \`${cat}\` | ${val.score !== null ? `${val.score}/100` : "N/A"} | ${val.finding_count} | ${val.finding_count === 0 ? "🟢 Clean" : "⚠️ Attention"} |`
  )
  .join("\n")}

### 🚨 Critical Security & Architecture Violations
${
  findings.filter((f) => f.severity === "critical" || f.severity === "high").length === 0
    ? "_No critical or high severity violations detected._"
    : findings
        .filter((f) => f.severity === "critical" || f.severity === "high")
        .slice(0, 5)
        .map(
          (f) =>
            `- **[${f.severity.toUpperCase()}]** \`${f.rule_id}\`: ${f.title} at \`${f.file}:${f.line_start}\``
        )
        .join("\n")
}

---
*Generated deterministically by [Entropy DevSecOps Engine](https://github.com/NaveenS-prog/entropy)*`;

    navigator.clipboard.writeText(prComment);
    setCopiedPrComment(true);
    setTimeout(() => setCopiedPrComment(false), 2500);
    setIsExportMenuOpen(false);
  };

  const tabs: Array<{
    id: WorkspaceId;
    label: string;
    shortcut: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: number | string | null;
    badgeStyle?: string;
  }> = [
    {
      id: "executive",
      label: "Executive Posture",
      shortcut: "1",
      icon: Activity,
    },
    {
      id: "findings",
      label: "Findings & AST Studio",
      shortcut: "2",
      icon: Terminal,
      badge: findings.length > 0 ? findings.length : null,
      badgeStyle:
        criticalCount > 0
          ? "bg-red-500/20 text-red-400 border border-red-500/40"
          : "bg-surface-3 text-ink-300 border border-border-subtle",
    },
    {
      id: "architecture",
      label: "Architecture Radar",
      shortcut: "3",
      icon: GitFork,
      badge: cycleCount > 0 ? `${cycleCount} Cycle` : null,
      badgeStyle: "bg-amber-500/20 text-amber-400 border border-amber-500/40",
    },
    {
      id: "routes",
      label: "Route Security",
      shortcut: "4",
      icon: Globe,
      badge: missingGuardCount > 0 ? `${missingGuardCount} Unguarded` : null,
      badgeStyle: "bg-orange-500/20 text-orange-400 border border-orange-500/40",
    },
    {
      id: "pr_delta",
      label: "PR Lifecycle & Delta",
      shortcut: "5",
      icon: GitPullRequest,
    },
    {
      id: "policies",
      label: "Policy Engine & Gates",
      shortcut: "6",
      icon: Sliders,
    },
  ];

  return (
    <div className="command-deck space-y-4">
      {/* Top Precision Command Header */}
      <div className="command-leaf bg-surface-1 border border-border-subtle rounded-xl p-4 sm:p-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* Left: Active Repo Info & Scan Switcher */}
          <div className="flex items-start sm:items-center gap-4 flex-wrap">
            <div className="relative">
              <button
                type="button"
                onClick={() => setIsSelectorOpen(!isSelectorOpen)}
                className="flex items-center gap-2.5 px-3 py-2 bg-surface-2 hover:bg-surface-3 border border-border-subtle hover:border-border-strong rounded-lg text-xs font-mono transition-all text-text-primary"
              >
                <FolderGit2 className="h-4 w-4 text-emerald-400 shrink-0" />
                <div className="text-left">
                  <div className="font-semibold text-text-primary flex items-center gap-1.5">
                    <span>
                      {activeScan?.repository?.name || activeScan?.repo_name || "Select Repository"}
                    </span>
                    <ChevronDown className="h-3 w-3 text-ink-400" />
                  </div>
                  <div className="text-[10px] text-ink-400 truncate max-w-[200px]">
                    {activeScan?.scan_id ? `Scan: ${activeScan.scan_id.slice(0, 8)}...` : "No scan loaded"}
                  </div>
                </div>
              </button>

              {/* Scan Dropdown */}
              {isSelectorOpen && (
                <div className="absolute left-0 mt-1.5 w-80 bg-surface-1 border border-border-strong rounded-xl shadow-2xl p-2 z-50 space-y-1">
                  <div className="px-2.5 py-1.5 text-[11px] font-semibold text-ink-400 uppercase tracking-wider flex items-center justify-between">
                    <span>Historical Scans ({scans.length})</span>
                    <button
                      onClick={() => {
                        setIsSelectorOpen(false);
                        setShowScanModal(true);
                      }}
                      className="text-emerald-400 hover:text-emerald-300 font-mono flex items-center gap-1"
                    >
                      <Play className="h-3 w-3" /> New
                    </button>
                  </div>
                  <div className="max-h-64 overflow-y-auto space-y-1">
                    {scans.length === 0 ? (
                      <div className="px-3 py-3 text-xs text-ink-500 text-center">
                        No previous scans discovered
                      </div>
                    ) : (
                      scans.map((s) => {
                        const isCurrent = s.scan_id === activeScan?.scan_id;
                        return (
                          <button
                            key={s.scan_id}
                            type="button"
                            onClick={() => {
                              onSelectScan(s.scan_id);
                              setIsSelectorOpen(false);
                            }}
                            className={`w-full text-left px-3 py-2 rounded-lg text-xs font-mono transition-colors flex items-center justify-between ${
                              isCurrent
                                ? "bg-surface-3 border border-border-strong text-white"
                                : "hover:bg-surface-2 text-ink-300"
                            }`}
                          >
                            <div className="truncate pr-2">
                              <div className="font-semibold text-text-primary truncate">
                                {s.repository?.name || s.repo_name || "Repo"}
                              </div>
                              <div className="text-[10px] text-ink-400 flex items-center gap-1.5">
                                <span>{s.scan_id.slice(0, 8)}</span>
                                {s.branch && <span>· {s.branch}</span>}
                              </div>
                            </div>
                            {s.score && (
                              <div className="text-right shrink-0">
                                <span className="font-semibold text-white">
                                  {s.score.total_score}
                                </span>
                                <span className="text-[10px] text-ink-400">/100</span>
                              </div>
                            )}
                          </button>
                        );
                      })
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Git Metadata Pills */}
            <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
              {activeScan?.repository?.branch && (
                <div className="flex items-center gap-1.5 px-2.5 py-1 bg-surface-2 border border-border-subtle rounded-md text-ink-300">
                  <GitBranch className="h-3.5 w-3.5 text-ink-400" />
                  <span className="text-text-primary font-medium">{activeScan.repository.branch}</span>
                </div>
              )}
              {activeScan?.repository?.commit_hash && (
                <div className="flex items-center gap-1.5 px-2.5 py-1 bg-surface-2 border border-border-subtle rounded-md text-ink-400">
                  <GitCommit className="h-3.5 w-3.5 text-ink-500" />
                  <span className="text-ink-300">
                    {activeScan.repository.commit_hash.slice(0, 7)}
                  </span>
                </div>
              )}
              {manifest?.repository && (
                <div className="flex items-center gap-1.5 px-2.5 py-1 bg-surface-2 border border-border-subtle rounded-md text-ink-400">
                  <FileCode className="h-3.5 w-3.5 text-ink-500" />
                  <span className="text-ink-300">
                    {manifest.repository.total_source_loc.toLocaleString()} LOC
                  </span>
                </div>
              )}
              {score?.severity_floor_applied && (
                <div className="flex items-center gap-1.5 px-2.5 py-1 bg-red-500/10 border border-red-500/30 rounded-md text-red-400 text-xs font-mono">
                  <AlertTriangle className="h-3.5 w-3.5" />
                  <span>Floor: {score.floor_reason?.slice(0, 32)}...</span>
                </div>
              )}
            </div>
          </div>

          {/* Right: Quick Action Controls & Export Dropdown */}
          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative">
              <button
                type="button"
                onClick={() => setIsExportMenuOpen(!isExportMenuOpen)}
                className="flex items-center gap-2 px-3 py-1.5 bg-surface-2 hover:bg-surface-3 border border-border-subtle hover:border-border-strong rounded-lg text-xs font-medium text-ink-200 hover:text-white transition-colors font-mono"
              >
                <ArrowDownToLine className="h-3.5 w-3.5 text-ink-400" />
                <span>Export Reports</span>
                <ChevronDown className="h-3 w-3 text-ink-400" />
              </button>

              {isExportMenuOpen && (
                <div className="absolute right-0 mt-1.5 w-64 bg-surface-1 border border-border-strong rounded-xl shadow-2xl p-2 z-50 space-y-1">
                  <button
                    type="button"
                    onClick={handleExportSarif}
                    className="w-full text-left px-3 py-2 rounded-lg text-xs font-mono hover:bg-surface-2 text-ink-200 hover:text-white transition-colors flex items-center gap-2.5"
                  >
                    <FileCode className="h-4 w-4 text-emerald-400 shrink-0" />
                    <div>
                      <div className="font-semibold">OASIS SARIF 2.1.0</div>
                      <div className="text-[10px] text-ink-400">Standard AST security findings</div>
                    </div>
                  </button>
                  <button
                    type="button"
                    onClick={handleExportJson}
                    className="w-full text-left px-3 py-2 rounded-lg text-xs font-mono hover:bg-surface-2 text-ink-200 hover:text-white transition-colors flex items-center gap-2.5"
                  >
                    <FileJson className="h-4 w-4 text-blue-400 shrink-0" />
                    <div>
                      <div className="font-semibold">JSON Scan Manifest</div>
                      <div className="text-[10px] text-ink-400">Complete raw score & AST dump</div>
                    </div>
                  </button>
                  <button
                    type="button"
                    onClick={handleCopyPrComment}
                    className="w-full text-left px-3 py-2 rounded-lg text-xs font-mono hover:bg-surface-2 text-ink-200 hover:text-white transition-colors flex items-center gap-2.5"
                  >
                    {copiedPrComment ? (
                      <Check className="h-4 w-4 text-emerald-400 shrink-0" />
                    ) : (
                      <GitPullRequest className="h-4 w-4 text-amber-400 shrink-0" />
                    )}
                    <div>
                      <div className="font-semibold">
                        {copiedPrComment ? "Copied to Clipboard!" : "Copy GitHub PR Comment"}
                      </div>
                      <div className="text-[10px] text-ink-400">Ready for CI / PR description</div>
                    </div>
                  </button>
                </div>
              )}
            </div>

            {/* Quick Trigger Scan Button */}
            <button
              type="button"
              onClick={() => setShowScanModal(true)}
              className="flex items-center gap-2 px-3 py-1.5 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-lg text-xs font-mono font-medium transition-colors"
            >
              <Play className="h-3.5 w-3.5 fill-current" />
              <span>New Scan</span>
            </button>

            {/* Health / Engine Pill */}
            <div className="flex items-center gap-1.5 px-2.5 py-1 bg-surface-2 border border-border-subtle rounded-md text-[11px] font-mono text-ink-400">
              <span
                className={`h-2 w-2 rounded-full ${
                  health?.status === "ok" || health?.status === "healthy"
                    ? "bg-emerald-400"
                    : "bg-emerald-400/80"
                }`}
              />
              <span>AST Engine v0.1.0</span>
            </div>
          </div>
        </div>
      </div>

      {/* 6 High-Density Operational Workspace Tabs */}
      <div className="command-tabs flex items-center gap-1.5 overflow-x-auto pb-1 scrollbar-none border-b border-border-subtle">
        {tabs.map((tab) => {
          const isActive = activeWorkspace === tab.id;
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              type="button"
              data-section={tab.id}
              onClick={() => onSelectWorkspace(tab.id)}
              className={`flex items-center gap-2 px-3.5 py-2.5 rounded-t-lg text-xs font-medium whitespace-nowrap transition-all border-b-2 font-mono ${
                isActive
                  ? "bg-surface-1 text-white border-emerald-400 shadow-sm"
                  : "text-ink-400 hover:text-ink-200 hover:bg-surface-2/60 border-transparent"
              }`}
            >
              <Icon className={`h-4 w-4 ${isActive ? "text-emerald-400" : "text-ink-500"}`} />
              <span>{tab.label}</span>
              <span className="text-[10px] text-ink-500 px-1 py-0.2 bg-surface-2 border border-border-subtle rounded">
                [{tab.shortcut}]
              </span>
              {tab.badge && (
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded-full font-mono ${
                    tab.badgeStyle || "bg-surface-3 text-ink-300"
                  }`}
                >
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Modal: Trigger Ingestion Scan */}
      {showScanModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-surface-1 border border-border-strong rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-5">
            <div className="flex items-center justify-between border-b border-border-subtle pb-4">
              <div className="flex items-center gap-2">
                <div className="h-8 w-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                  <Play className="h-4 w-4 fill-current" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-white font-mono">
                    Deterministic AST Ingestion Scan
                  </h3>
                  <p className="text-xs text-ink-400">
                    Parse source tree, extract AST models & evaluate rules
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowScanModal(false)}
                className="text-ink-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleStartScan} className="space-y-4">
              <div>
                <label className="block text-xs font-mono font-medium text-ink-300 mb-1.5">
                  Absolute Repository Path *
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. C:\Users\VISHANTH R\Downloads\entropy-main or /workspace/repo"
                  value={newScanPath}
                  onChange={(e) => setNewScanPath(e.target.value)}
                  className="w-full bg-surface-2 border border-border-subtle focus:border-emerald-400 rounded-lg px-3.5 py-2 text-xs font-mono text-white placeholder-ink-500 outline-none transition-colors"
                />
              </div>

              <div>
                <label className="block text-xs font-mono font-medium text-ink-300 mb-1.5">
                  Repository Name (Optional)
                </label>
                <input
                  type="text"
                  placeholder="e.g. entropy-core"
                  value={newScanName}
                  onChange={(e) => setNewScanName(e.target.value)}
                  className="w-full bg-surface-2 border border-border-subtle focus:border-emerald-400 rounded-lg px-3.5 py-2 text-xs font-mono text-white placeholder-ink-500 outline-none transition-colors"
                />
              </div>

              {scanModalError && (
                <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-xs font-mono text-red-400 flex items-start gap-2">
                  <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
                  <span>{scanModalError}</span>
                </div>
              )}

              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowScanModal(false)}
                  className="px-4 py-2 bg-surface-2 hover:bg-surface-3 text-ink-300 rounded-lg text-xs font-mono transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isScanning}
                  className="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-black font-semibold rounded-lg text-xs font-mono flex items-center gap-2 transition-colors"
                >
                  {isScanning ? (
                    <>
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      <span>Parsing AST...</span>
                    </>
                  ) : (
                    <>
                      <Play className="h-3.5 w-3.5 fill-current" />
                      <span>Execute Scan</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

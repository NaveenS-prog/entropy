"use client";

import { useEffect, useState } from "react";
import {
  compareScans,
  fetchHealth,
  getFindings,
  getManifest,
  getRepositoryTrend,
  getScore,
  listRepositoryScans,
  listScans,
  triggerScan,
} from "@/lib/api";
import {
  DebtCategory,
  DebtScoreResult,
  Finding,
  PaginatedScanSnapshots,
  RepositoryManifest,
  RepositoryScanResult,
  RepositoryTrendResponse,
  ScanComparisonResult,
  SystemHealth,
} from "@/types";
import { FindingsViewer } from "@/components/findings/FindingsViewer";
import { ScoreBanner } from "@/components/dashboard/ScoreBanner";
import { CategoryMatrix } from "@/components/dashboard/CategoryMatrix";
import { ScoreTrendChart } from "@/components/history/ScoreTrendChart";
import { ScanHistoryTable } from "@/components/history/ScanHistoryTable";
import { ScanComparisonView } from "@/components/comparison/ScanComparisonView";
import { PRWorkflowView } from "@/components/github/PRWorkflowView";
import {
  FolderGit2,
  FileCode,
  Files,
  FileWarning,
  EyeOff,
  CheckCircle2,
  AlertCircle,
  Loader2,
  Code2,
  FolderTree,
  Search,
  ChevronDown,
  Terminal,
  FileText,
  Braces,
  History,
  GitCompare,
  GitPullRequest,
} from "lucide-react";

const SCAN_STEPS = [
  "Scanning repository...",
  "Discovering files...",
  "Detecting languages...",
  "Building manifest...",
  "Scan complete.",
];

export default function RepositoryIngestionDashboard() {
  const [repoPath, setRepoPath] = useState("");
  const [repoName, setRepoName] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanStepIndex, setScanStepIndex] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const [scans, setScans] = useState<RepositoryScanResult[]>([]);
  const [activeScan, setActiveScan] = useState<RepositoryScanResult | null>(null);
  const [manifest, setManifest] = useState<RepositoryManifest | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [isLoadingFindings, setIsLoadingFindings] = useState<boolean>(false);
  const [score, setScore] = useState<DebtScoreResult | null>(null);
  const [isLoadingScore, setIsLoadingScore] = useState<boolean>(false);
  const [selectedCategory, setSelectedCategory] = useState<DebtCategory | null>(null);
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedLanguageFilter, setSelectedLanguageFilter] = useState<string>("ALL");
  const [showJsonManifest, setShowJsonManifest] = useState(false);

  // Phase 10 History & Comparison State and Phase 12 PR Workflow State
  const [activeTab, setActiveTab] = useState<"overview" | "history" | "comparison" | "pull_requests">("overview");
  const [history, setHistory] = useState<PaginatedScanSnapshots | null>(null);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  const [trend, setTrend] = useState<RepositoryTrendResponse | null>(null);
  const [isLoadingTrend, setIsLoadingTrend] = useState(false);
  const [comparison, setComparison] = useState<ScanComparisonResult | null>(null);
  const [isLoadingComparison, setIsLoadingComparison] = useState(false);
  const [comparisonError, setComparisonError] = useState<string | null>(null);

  const loadHistoryAndTrend = async (repoId: string, page = 1) => {
    if (!repoId) return;
    setIsLoadingHistory(true);
    setIsLoadingTrend(true);
    try {
      const [histData, trendData] = await Promise.all([
        listRepositoryScans(repoId, page).catch(() => null),
        getRepositoryTrend(repoId).catch(() => null),
      ]);
      setHistory(histData);
      setTrend(trendData);
    } finally {
      setIsLoadingHistory(false);
      setIsLoadingTrend(false);
    }
  };

  const handleCompareScans = async (currId: string, prevId: string) => {
    setIsLoadingComparison(true);
    setComparisonError(null);
    setActiveTab("comparison");
    try {
      const comp = await compareScans(currId, prevId);
      setComparison(comp);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to compare scans";
      setComparisonError(msg);
      setComparison(null);
    } finally {
      setIsLoadingComparison(false);
    }
  };

  const loadFindingsForScan = async (scanId: string) => {
    setIsLoadingFindings(true);
    try {
      const f = await getFindings(scanId);
      setFindings(f);
    } catch (err) {
      console.error("Failed to load findings:", err);
      setFindings([]);
    } finally {
      setIsLoadingFindings(false);
    }
  };

  const loadScoreForScan = async (scanId: string) => {
    setIsLoadingScore(true);
    try {
      const s = await getScore(scanId);
      setScore(s);
    } catch (err) {
      console.error("Failed to load score:", err);
      setScore(null);
    } finally {
      setIsLoadingScore(false);
    }
  };

  useEffect(() => {
    async function init() {
      try {
        const [healthData, scanList] = await Promise.all([
          fetchHealth().catch(() => null),
          listScans().catch(() => []),
        ]);
        setHealth(healthData);
        setScans(scanList);
        if (scanList.length > 0) {
          const first = scanList[0];
          setActiveScan(first);
          if (first.manifest) {
            setManifest(first.manifest);
          } else {
            getManifest(first.scan_id).then(setManifest).catch(() => null);
          }
          loadFindingsForScan(first.scan_id);
          loadScoreForScan(first.scan_id);
          if (first.repository.repository_id) {
            loadHistoryAndTrend(first.repository.repository_id);
          }
        }
      } catch (err) {
        console.error("Initialization error:", err);
      }
    }
    init();
  }, []);

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!repoPath.trim()) return;

    setError(null);
    setIsScanning(true);
    setScanStepIndex(0);

    const interval = setInterval(() => {
      setScanStepIndex((prev) => (prev < 3 ? prev + 1 : prev));
    }, 450);

    try {
      const result = await triggerScan(repoPath.trim(), repoName.trim() || undefined);
      clearInterval(interval);
      setScanStepIndex(4);

      setScans((prev) => [result, ...prev.filter((s) => s.scan_id !== result.scan_id)]);
      setActiveScan(result);
      if (result.manifest) {
        setManifest(result.manifest);
      } else {
        const fetchedManifest = await getManifest(result.scan_id);
        setManifest(fetchedManifest);
      }
      loadFindingsForScan(result.scan_id);
      loadScoreForScan(result.scan_id);
      if (result.repository.repository_id) {
        loadHistoryAndTrend(result.repository.repository_id);
      }
    } catch (err: unknown) {
      clearInterval(interval);
      const errorMessage = err instanceof Error ? err.message : "Failed to scan repository";
      setError(errorMessage);
    } finally {
      setIsScanning(false);
    }
  };

  const handleSelectScan = async (scanId: string) => {
    const found = scans.find((s) => s.scan_id === scanId);
    if (!found) return;
    setActiveScan(found);
    if (found.manifest) {
      setManifest(found.manifest);
    } else {
      try {
        const m = await getManifest(found.scan_id);
        setManifest(m);
      } catch {
        setManifest(null);
      }
    }
    loadFindingsForScan(found.scan_id);
    loadScoreForScan(found.scan_id);
    if (found.repository.repository_id) {
      loadHistoryAndTrend(found.repository.repository_id);
    }
  };

  const filteredFiles = (manifest?.files || []).filter((f) => {
    const matchesSearch =
      f.path.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.language.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesLang =
      selectedLanguageFilter === "ALL" ||
      f.language.toLowerCase() === selectedLanguageFilter.toLowerCase();
    return matchesSearch && matchesLang;
  });

  return (
    <div className="space-y-8">
      {/* Top Header & Server Status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <FolderGit2 className="h-6 w-6 text-emerald-400" />
            <span>Entropy Security Debt Engine</span>
            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-emerald-950/70 border border-emerald-800 text-emerald-300">
              Phase 1, 2, 3 &amp; 4
            </span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Safe file discovery, Python AST extraction, deterministic Error Handling Debt detection, and evidence-derived Entropy scoring.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {scans.length > 0 && (
            <div className="relative">
              <select
                value={activeScan?.scan_id || ""}
                onChange={(e) => handleSelectScan(e.target.value)}
                className="appearance-none bg-slate-900 border border-slate-700 text-xs font-semibold text-white rounded-lg pl-3 pr-8 py-2 focus:outline-none focus:border-emerald-500 cursor-pointer"
              >
                {scans.map((s) => (
                  <option key={s.scan_id} value={s.scan_id}>
                    {s.repository.name} ({s.status})
                  </option>
                ))}
              </select>
              <ChevronDown className="h-3.5 w-3.5 text-slate-400 absolute right-2.5 top-3 pointer-events-none" />
            </div>
          )}

          {health && (
            <div className="flex items-center gap-2 text-xs text-slate-400 font-mono bg-slate-900 px-3 py-2 rounded-lg border border-slate-800">
              <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
              <span>Backend {health.version}</span>
              <span className="text-slate-600">|</span>
              <span>Engine {health.status}</span>
            </div>
          )}
        </div>
      </div>

      {/* Top Workspace Mode Selector */}
      <div className="flex items-center gap-2 border-b border-border pb-3">
        <button
          onClick={() => setActiveTab("overview")}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-colors ${
            activeTab !== "pull_requests"
              ? "bg-emerald-600 text-white shadow-sm"
              : "text-slate-400 hover:text-white hover:bg-slate-800/60"
          }`}
        >
          <FolderGit2 className="w-4 h-4" />
          <span>Local Repository Scanner</span>
        </button>

        <button
          onClick={() => setActiveTab("pull_requests")}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-colors ${
            activeTab === "pull_requests"
              ? "bg-indigo-600 text-white shadow-sm"
              : "text-slate-400 hover:text-white hover:bg-slate-800/60"
          }`}
        >
          <GitPullRequest className="w-4 h-4" />
          <span>GitHub Pull Requests</span>
          <span className="px-1.5 py-0.5 rounded text-[10px] bg-indigo-950 text-indigo-300 border border-indigo-800 font-mono">
            Phase 12
          </span>
        </button>
      </div>

      {activeTab === "pull_requests" ? (
        <PRWorkflowView />
      ) : (
        <>
          {/* Main Scan Trigger Box */}
          <div className="bg-card border border-border rounded-xl p-6 shadow-sm">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-2 flex items-center gap-2">
          <Terminal className="h-4 w-4 text-emerald-400" />
          <span>Scan Repository</span>
        </h2>
        <p className="text-xs text-slate-400 mb-5">
          Enter the absolute or relative path to a local code repository. Entropy inspects file structures,
          detects programming languages, respects <code className="text-slate-300">.gitignore</code>, and guarantees zero code execution.
        </p>

        <form onSubmit={handleStartScan} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                Repository Path <span className="text-red-400">*</span>
              </label>
              <input
                type="text"
                placeholder="/home/user/my-project"
                value={repoPath}
                onChange={(e) => setRepoPath(e.target.value)}
                required
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3.5 py-2.5 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                Display Name (optional)
              </label>
              <input
                type="text"
                placeholder="e.g. backend-api"
                value={repoName}
                onChange={(e) => setRepoName(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3.5 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>

          {/* Quick preset paths */}
          <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px] text-slate-400">
            <span className="font-semibold text-slate-500">Quick Paths:</span>
            <button
              type="button"
              onClick={() => {
                setRepoPath("/home/naveen/Entropy");
                setRepoName("entropy-workspace");
              }}
              className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded border border-slate-700 font-mono"
            >
              /home/naveen/Entropy
            </button>
            <button
              type="button"
              onClick={() => {
                setRepoPath("/home/naveen/Entropy/backend/tests/fixtures/clean_python_project");
                setRepoName("clean-python-project");
              }}
              className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded border border-slate-700 font-mono"
            >
              clean_python_project
            </button>
            <button
              type="button"
              onClick={() => {
                setRepoPath("/home/naveen/Entropy/backend/tests/fixtures/mixed_language_project");
                setRepoName("mixed-language-project");
              }}
              className="bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded border border-slate-700 font-mono"
            >
              mixed_language_project
            </button>
          </div>

          <div className="pt-2 flex items-center justify-between">
            <div className="text-[11px] text-slate-400 font-mono flex items-center gap-2">
              <span className="h-1.5 w-1.5 rounded-full bg-slate-500" />
              <span>Limits: 2MB/file • 50,000 files max • Static AST Only</span>
            </div>

            <button
              type="submit"
              disabled={isScanning || !repoPath.trim()}
              className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-semibold px-5 py-2.5 rounded-lg text-xs transition-colors shadow-md cursor-pointer"
            >
              {isScanning ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>{SCAN_STEPS[scanStepIndex]}</span>
                </>
              ) : (
                <>
                  <FolderGit2 className="h-4 w-4" />
                  <span>Scan Repository</span>
                </>
              )}
            </button>
          </div>
        </form>

        {/* Scan Progress State */}
        {isScanning && (
          <div className="mt-5 p-4 rounded-lg bg-slate-900 border border-slate-800 font-mono text-xs">
            <div className="flex items-center gap-2 text-emerald-400 font-semibold mb-2">
              <Loader2 className="h-4 w-4 animate-spin" />
              <span>{SCAN_STEPS[scanStepIndex]}</span>
            </div>
            <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
              <div
                className="bg-emerald-500 h-full transition-all duration-300"
                style={{ width: `${((scanStepIndex + 1) / SCAN_STEPS.length) * 100}%` }}
              />
            </div>
          </div>
        )}

        {/* Error notification */}
        {error && (
          <div className="mt-5 p-4 rounded-lg bg-red-950/40 border border-red-900/60 text-red-200 text-xs flex items-start gap-3">
            <AlertCircle className="h-4 w-4 text-red-400 mt-0.5 shrink-0" />
            <div>
              <p className="font-semibold text-red-300">Scan Error</p>
              <p className="mt-0.5 font-mono text-[11px]">{error}</p>
            </div>
          </div>
        )}
      </div>

      {/* Real Scan Results */}
      {manifest && activeScan ? (
        <div className="space-y-6">
          {/* Navigation Tabs */}
          <div className="flex items-center gap-2 border-b border-border pb-3">
            <button
              onClick={() => setActiveTab("overview")}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-colors ${
                activeTab === "overview"
                  ? "bg-emerald-600 text-white shadow-sm"
                  : "text-slate-400 hover:text-white hover:bg-slate-800/60"
              }`}
            >
              <FolderGit2 className="w-4 h-4" />
              <span>Overview</span>
            </button>

            <button
              onClick={() => {
                setActiveTab("history");
                if (activeScan.repository.repository_id) {
                  loadHistoryAndTrend(activeScan.repository.repository_id);
                }
              }}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-colors ${
                activeTab === "history"
                  ? "bg-emerald-600 text-white shadow-sm"
                  : "text-slate-400 hover:text-white hover:bg-slate-800/60"
              }`}
            >
              <History className="w-4 h-4" />
              <span>Scan History &amp; Trends</span>
              {history && history.total > 0 && (
                <span className="ml-1 px-1.5 py-0.5 rounded-full text-[10px] bg-slate-900 font-mono text-emerald-300">
                  {history.total}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab("comparison")}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-colors ${
                activeTab === "comparison"
                  ? "bg-emerald-600 text-white shadow-sm"
                  : "text-slate-400 hover:text-white hover:bg-slate-800/60"
              }`}
            >
              <GitCompare className="w-4 h-4" />
              <span>Compare Scans</span>
              {comparison && (
                <span className="ml-1 px-1.5 py-0.5 rounded-full text-[10px] bg-slate-900 font-mono text-emerald-300">
                  active
                </span>
              )}
            </button>
          </div>

          {activeTab === "overview" && (
            <div className="space-y-6">
              {/* Entropy Debt Score Banner (Phase 4 Engine) */}
              {score && (
                <ScoreBanner
                  score={score}
                  repository={activeScan.repository}
                  durationMs={activeScan.duration_ms}
                />
              )}

          {/* Architectural Debt Categories Breakdown */}
          {score && score.category_scores && (
            <CategoryMatrix
              categories={score.category_scores}
              selectedCategory={selectedCategory}
              onSelectCategory={setSelectedCategory}
            />
          )}

          {/* Summary Stat Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
            <div className="bg-card border border-border rounded-xl p-4">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Files className="h-3.5 w-3.5 text-cyan-400" />
                Total Files
              </span>
              <p className="text-2xl font-bold text-white mt-1 font-mono">
                {manifest.repository.total_files}
              </p>
              <span className="text-[10px] text-slate-400">Inspected files</span>
            </div>

            <div className="bg-card border border-border rounded-xl p-4">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <FileCode className="h-3.5 w-3.5 text-emerald-400" />
                Source Files
              </span>
              <p className="text-2xl font-bold text-emerald-400 mt-1 font-mono">
                {manifest.repository.source_files}
              </p>
              <span className="text-[10px] text-slate-400">Recognized code files</span>
            </div>

            <div className="bg-card border border-border rounded-xl p-4">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <EyeOff className="h-3.5 w-3.5 text-slate-400" />
                Ignored
              </span>
              <p className="text-2xl font-bold text-slate-300 mt-1 font-mono">
                {manifest.repository.ignored_files}
              </p>
              <span className="text-[10px] text-slate-400">.gitignore & rules</span>
            </div>

            <div className="bg-card border border-border rounded-xl p-4">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <FileWarning className="h-3.5 w-3.5 text-amber-400" />
                Skipped Files
              </span>
              <p className="text-2xl font-bold text-amber-400 mt-1 font-mono">
                {manifest.repository.skipped_files}
              </p>
              <span className="text-[10px] text-slate-400">Size / binary / errors</span>
            </div>

            <div className="bg-card border border-border rounded-xl p-4">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Code2 className="h-3.5 w-3.5 text-purple-400" />
                Total LOC
              </span>
              <p className="text-2xl font-bold text-purple-300 mt-1 font-mono">
                {manifest.repository.total_source_loc.toLocaleString()}
              </p>
              <span className="text-[10px] text-slate-400">Lines of source code</span>
            </div>

            <div className="bg-card border border-border rounded-xl p-4">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <FileText className="h-3.5 w-3.5 text-indigo-400" />
                Source Size
              </span>
              <p className="text-2xl font-bold text-indigo-300 mt-1 font-mono">
                {(manifest.repository.total_source_size / 1024).toFixed(1)} <span className="text-xs">KB</span>
              </p>
              <span className="text-[10px] text-slate-400">Uncompressed bytes</span>
            </div>
          </div>

          {/* Languages Breakdown */}
          <div className="bg-card border border-border rounded-xl p-6">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-2">
              <Code2 className="h-4 w-4 text-emerald-400" />
              <span>Languages Detected</span>
            </h3>

            {Object.keys(manifest.languages).length === 0 ? (
              <p className="text-xs text-slate-400 font-mono">No recognized programming languages detected.</p>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {Object.entries(manifest.languages).map(([lang, count]) => {
                  const isSupported = lang.toLowerCase() === "python";
                  return (
                    <div
                      key={lang}
                      className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between"
                    >
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-sm text-white capitalize">{lang}</span>
                          <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-900 px-2 py-0.5 rounded font-bold">
                            {count}
                          </span>
                        </div>
                        <div className="mt-1.5">
                          {isSupported ? (
                            <span className="text-[10px] text-emerald-400 font-mono flex items-center gap-1">
                              <CheckCircle2 className="h-3 w-3" />
                              <span>Analysis Supported</span>
                            </span>
                          ) : (
                            <span className="text-[10px] text-amber-400/90 font-mono flex items-center gap-1">
                              <AlertCircle className="h-3 w-3" />
                              <span>language_detected_but_analyzer_unavailable</span>
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Error Handling Debt Findings (Phase 3 Engine) */}
          <FindingsViewer
            scanId={activeScan?.scan_id || ""}
            findings={findings}
            selectedCategory={selectedCategory}
            isLoading={isLoadingFindings}
          />

          {/* Source Files Explorer */}
          <div className="bg-card border border-border rounded-xl p-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
              <div>
                <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <FolderTree className="h-4 w-4 text-emerald-400" />
                  <span>Repository Manifest — Discovered Source Files</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Showing {filteredFiles.length} of {manifest.files.length} source files
                </p>
              </div>

              {/* Filters */}
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search className="h-3.5 w-3.5 text-slate-400 absolute left-2.5 top-2.5 pointer-events-none" />
                  <input
                    type="text"
                    placeholder="Search file path..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="bg-slate-900 border border-slate-700 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-emerald-500 w-44 sm:w-56"
                  />
                </div>

                <select
                  value={selectedLanguageFilter}
                  onChange={(e) => setSelectedLanguageFilter(e.target.value)}
                  className="bg-slate-900 border border-slate-700 text-xs text-white rounded-lg px-3 py-1.5 focus:outline-none focus:border-emerald-500 cursor-pointer capitalize"
                >
                  <option value="ALL">All Languages</option>
                  {Object.keys(manifest.languages).map((l) => (
                    <option key={l} value={l}>
                      {l}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="border border-slate-800 rounded-lg overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900/80 text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-2.5">Relative Path</th>
                    <th className="px-4 py-2.5">Language</th>
                    <th className="px-4 py-2.5">Size</th>
                    <th className="px-4 py-2.5">Lines (LOC)</th>
                    <th className="px-4 py-2.5">Analysis Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {filteredFiles.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-4 py-8 text-center text-slate-500">
                        No source files match the filter.
                      </td>
                    </tr>
                  ) : (
                    filteredFiles.map((f, idx) => (
                      <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
                        <td className="px-4 py-2 text-white font-medium">{f.path}</td>
                        <td className="px-4 py-2">
                          <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 capitalize">
                            {f.language}
                          </span>
                        </td>
                        <td className="px-4 py-2 text-slate-400">
                          {f.size > 1024 ? `${(f.size / 1024).toFixed(1)} KB` : `${f.size} B`}
                        </td>
                        <td className="px-4 py-2 text-slate-400">{f.line_count ?? "—"}</td>
                        <td className="px-4 py-2">
                          {f.analysis_supported ? (
                            <span className="text-[10px] text-emerald-400 bg-emerald-950/60 border border-emerald-900 px-2 py-0.5 rounded font-mono">
                              analysis_supported
                            </span>
                          ) : (
                            <span className="text-[10px] text-amber-400/90 bg-amber-950/40 border border-amber-900/60 px-2 py-0.5 rounded font-mono">
                              {f.skip_reason || "language_detected_but_analyzer_unavailable"}
                            </span>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Skipped Files Table (if any) */}
          {manifest.skipped_files && manifest.skipped_files.length > 0 && (
            <div className="bg-card border border-border rounded-xl p-6">
              <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-2 flex items-center gap-2">
                <FileWarning className="h-4 w-4 text-amber-400" />
                <span>Skipped Files ({manifest.skipped_files.length})</span>
              </h3>
              <p className="text-xs text-slate-400 mb-4">
                Files excluded safely during ingestion due to size boundaries, binary detection, or unreadable encoding.
              </p>

              <div className="border border-slate-800 rounded-lg overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900/80 text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800">
                    <tr>
                      <th className="px-4 py-2.5">File Path</th>
                      <th className="px-4 py-2.5">Size</th>
                      <th className="px-4 py-2.5">Skip Reason</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {manifest.skipped_files.map((sf, idx) => (
                      <tr key={idx} className="hover:bg-slate-900/40">
                        <td className="px-4 py-2 text-white">{sf.path}</td>
                        <td className="px-4 py-2 text-slate-400">
                          {sf.size > 1024 ? `${(sf.size / 1024).toFixed(1)} KB` : `${sf.size} B`}
                        </td>
                        <td className="px-4 py-2 text-amber-400 text-[11px]">{sf.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Raw Manifest JSON Viewer */}
          <div className="bg-card border border-border rounded-xl p-4">
            <button
              onClick={() => setShowJsonManifest(!showJsonManifest)}
              className="w-full flex items-center justify-between text-xs font-semibold text-slate-300 hover:text-white"
            >
              <div className="flex items-center gap-2">
                <Braces className="h-4 w-4 text-emerald-400" />
                <span>Repository Manifest JSON Payload</span>
                <span className="text-[10px] text-emerald-400 bg-emerald-950/60 border border-emerald-800/60 px-2 py-0.5 rounded font-mono">
                  GET /scans/{activeScan?.scan_id}/manifest
                </span>
              </div>
              <span className="text-slate-500">{showJsonManifest ? "Hide JSON" : "View JSON"}</span>
            </button>

            {showJsonManifest && (
              <div className="mt-4 pt-3 border-t border-border/80">
                <pre className="bg-slate-950 p-4 rounded-lg border border-slate-800 text-[11px] font-mono text-emerald-300/90 overflow-x-auto max-h-96">
                  {JSON.stringify(manifest, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Scan History & Trend Intelligence Tab */}
      {activeTab === "history" && (
        <div className="space-y-6">
          <ScoreTrendChart
            trend={trend}
            isLoading={isLoadingTrend}
            onSelectScan={handleSelectScan}
          />
          <ScanHistoryTable
            history={history}
            activeScanId={activeScan?.scan_id}
            isLoading={isLoadingHistory}
            onSelectScan={handleSelectScan}
            onCompareScans={handleCompareScans}
            onPageChange={(p) => {
              if (activeScan?.repository.repository_id) {
                loadHistoryAndTrend(activeScan.repository.repository_id, p);
              }
            }}
          />
        </div>
      )}

      {/* Scan Comparison Tab */}
      {activeTab === "comparison" && (
        <div className="space-y-6">
          {isLoadingComparison ? (
            <div className="bg-card border border-border rounded-xl p-12 flex flex-col items-center justify-center min-h-[300px] text-center space-y-3">
              <Loader2 className="w-8 h-8 text-emerald-400 animate-spin" />
              <p className="text-sm font-semibold text-slate-300">
                Computing deterministic comparison...
              </p>
              <p className="text-xs text-slate-500 font-mono">
                Matching fingerprints, computing score and category deltas
              </p>
            </div>
          ) : comparisonError ? (
            <div className="bg-card border border-red-900/60 rounded-xl p-6 text-xs text-red-300 space-y-2">
              <div className="flex items-center gap-2 text-red-400 font-semibold">
                <AlertCircle className="w-4 h-4" />
                <span>Comparison Failed</span>
              </div>
              <p className="font-mono">{comparisonError}</p>
            </div>
          ) : comparison ? (
            <ScanComparisonView
              comparison={comparison}
              onClose={() => setActiveTab("history")}
            />
          ) : (
            <div className="bg-card border border-border rounded-xl p-10 text-center space-y-4">
              <GitCompare className="w-10 h-10 text-slate-500 mx-auto" />
              <div className="space-y-1">
                <h3 className="text-sm font-bold text-white">No Active Comparison</h3>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  Go to the <strong>Scan History &amp; Trends</strong> tab and choose any two scans to run a deterministic comparison.
                </p>
              </div>
              <button
                onClick={() => setActiveTab("history")}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition-colors"
              >
                Open Scan History
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  ) : (
        /* Empty Welcome State */
        <div className="border border-dashed border-slate-800 rounded-2xl p-12 text-center bg-card/30">
          <div className="h-14 w-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center mx-auto mb-4">
            <FolderGit2 className="h-7 w-7" />
          </div>
          <h2 className="text-lg font-bold text-white tracking-tight">No Repository Manifest Loaded</h2>
          <p className="text-xs text-slate-400 max-w-md mx-auto mt-2 leading-relaxed">
            Enter a local code repository path above and click <strong>Scan Repository</strong> to discover files,
            classify languages, and generate a complete static analysis manifest.
          </p>
        </div>
      )}
        </>
      )}
    </div>
  );
}

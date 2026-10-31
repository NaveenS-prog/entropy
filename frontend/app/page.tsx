"use client";

import { useEffect, useState } from "react";
import {
  compareScans,
  fetchHealth,
  getFindings,
  getManifest,
  getRepositoryTrend,
  getScan,
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
  AlertCircle,
  Loader2,
} from "lucide-react";

const SCAN_STEPS = [
  "Scanning repository...",
  "Discovering files...",
  "Detecting languages...",
  "Building manifest...",
  "Scan complete",
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
  const [selectedCategory, setSelectedCategory] = useState<DebtCategory | null>(null);
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedLanguageFilter, setSelectedLanguageFilter] = useState<string>("ALL");
  const [showJsonManifest, setShowJsonManifest] = useState(false);

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
    try {
      const s = await getScore(scanId);
      setScore(s);
    } catch (err) {
      console.error("Failed to load score:", err);
      setScore(null);
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
          try {
            const fullScan = await getScan(first.scan_id);
            setActiveScan(fullScan);
            if (fullScan.manifest) {
              setManifest(fullScan.manifest);
            } else {
              getManifest(fullScan.scan_id).then(setManifest).catch(() => null);
            }
            loadFindingsForScan(fullScan.scan_id);
            loadScoreForScan(fullScan.scan_id);
            if (fullScan.repository?.repository_id) {
              loadHistoryAndTrend(fullScan.repository.repository_id);
            }
          } catch {
            const fallback: RepositoryScanResult = {
              ...first,
              repository: first.repository || {
                name: (first as any).repo_name || "Repository",
                path: (first as any).repo_path || "",
                branch: first.branch,
                commit_hash: first.commit_hash,
                total_files: 0,
                scannable_files: 0,
                total_loc: 0,
              },
              findings: first.findings || [],
              analyzers_executed: first.analyzers_executed || [],
              errors: first.errors || [],
            };
            setActiveScan(fallback);
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
      if (result.repository?.repository_id) {
        loadHistoryAndTrend(result.repository.repository_id);
      }
    } catch (err: unknown) {
      clearInterval(interval);
      let errorMessage = err instanceof Error ? err.message : "Failed to scan repository";
      if (
        errorMessage.toLowerCase().includes("failed to fetch") ||
        errorMessage.toLowerCase().includes("networkerror")
      ) {
        errorMessage =
          "Cannot reach backend API. Ensure your backend service is running.";
      }
      setError(errorMessage);
    } finally {
      setIsScanning(false);
    }
  };

  const handleSelectScan = async (scanId: string) => {
    try {
      const full = await getScan(scanId);
      setActiveScan(full);
      if (full.manifest) {
        setManifest(full.manifest);
      } else {
        const m = await getManifest(full.scan_id).catch(() => null);
        setManifest(m);
      }
      loadFindingsForScan(full.scan_id);
      loadScoreForScan(full.scan_id);
      if (full.repository?.repository_id) {
        loadHistoryAndTrend(full.repository.repository_id);
      }
    } catch (err) {
      console.error("Failed to load selected scan:", err);
      const found = scans.find((s) => s.scan_id === scanId);
      if (found) {
        setActiveScan({
          ...found,
          repository: found.repository || {
            name: (found as any).repo_name || "Repository",
            path: (found as any).repo_path || "",
            branch: found.branch,
            commit_hash: found.commit_hash,
            total_files: 0,
            scannable_files: 0,
            total_loc: 0,
          },
          findings: found.findings || [],
          analyzers_executed: found.analyzers_executed || [],
          errors: found.errors || [],
        });
      }
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
    <div className="space-y-6">
      {/* Top Header & Server Status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <h1 className="text-lg font-semibold text-white tracking-tight flex items-center gap-2">
            <FolderGit2 className="h-5 w-5 text-ink-300" />
            <span>Repository security debt</span>
          </h1>
          <p className="text-xs text-ink-400 mt-0.5">
            Deterministic AST analysis and evidence-grounded architectural scoring
          </p>
        </div>

        <div className="flex items-center gap-3">
          {scans.length > 0 && (
            <div className="relative">
              <select
                value={activeScan?.scan_id || ""}
                onChange={(e) => handleSelectScan(e.target.value)}
                className="appearance-none bg-ink-850 border border-border text-xs text-ink-200 rounded-md pl-3 pr-8 py-1.5 focus:outline-none focus:border-ink-500 cursor-pointer"
              >
                {scans.map((s) => {
                  const repoName = s.repository?.name || s.repo_name || "Repository";
                  return (
                    <option key={s.scan_id} value={s.scan_id}>
                      {repoName} ({s.status})
                    </option>
                  );
                })}
              </select>
              <ChevronDown className="h-3 w-3 text-ink-400 absolute right-2.5 top-2.5 pointer-events-none" />
            </div>
          )}

          {health ? (
            <div className="flex items-center gap-2 text-xs text-ink-400 font-mono bg-ink-850 px-2.5 py-1.5 rounded-md border border-border">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
              <span>v{health.version}</span>
              <span className="text-ink-600">/</span>
              <span>{health.status}</span>
            </div>
          ) : (
            <div className="flex items-center gap-2 text-xs text-amber-300 font-mono bg-ink-850 border border-border px-2.5 py-1.5 rounded-md">
              <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
              <span>Offline</span>
            </div>
          )}
        </div>
      </div>

      {/* Primary Workspace Mode Selector */}
      <div className="flex items-center gap-1.5 border-b border-border pb-3">
        <button
          onClick={() => setActiveTab("overview")}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
            activeTab !== "pull_requests"
              ? "bg-ink-800 text-white border border-border"
              : "text-ink-400 hover:text-white"
          }`}
        >
          <FolderGit2 className="w-3.5 h-3.5" />
          <span>Repository scanner</span>
        </button>

        <button
          onClick={() => setActiveTab("pull_requests")}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
            activeTab === "pull_requests"
              ? "bg-ink-800 text-white border border-border"
              : "text-ink-400 hover:text-white"
          }`}
        >
          <GitPullRequest className="w-3.5 h-3.5" />
          <span>Pull requests</span>
        </button>
      </div>

      {activeTab === "pull_requests" ? (
        <PRWorkflowView />
      ) : (
        <>
          {/* Main Scan Trigger Box */}
          <div className="bg-card border border-border rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xs font-medium text-ink-200 uppercase tracking-wider flex items-center gap-2">
                  <Terminal className="h-3.5 w-3.5 text-ink-400" />
                  <span>Scan repository</span>
                </h2>
                <p className="text-xs text-ink-400 mt-0.5">
                  Enter a local filesystem path or remote Git URL. Zero untrusted code execution.
                </p>
              </div>
            </div>

            <form onSubmit={handleStartScan} className="space-y-3">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="md:col-span-2">
                  <label className="block text-xs text-ink-400 mb-1">
                    Path or Git URL
                  </label>
                  <input
                    type="text"
                    placeholder="/path/to/project or https://github.com/owner/repo"
                    value={repoPath}
                    onChange={(e) => setRepoPath(e.target.value)}
                    required
                    className="w-full bg-ink-850 border border-border rounded-md px-3 py-2 text-xs text-white placeholder-ink-500 font-mono focus:outline-none focus:border-ink-500"
                  />
                </div>

                <div>
                  <label className="block text-xs text-ink-400 mb-1">
                    Display name (optional)
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. backend-api"
                    value={repoName}
                    onChange={(e) => setRepoName(e.target.value)}
                    className="w-full bg-ink-850 border border-border rounded-md px-3 py-2 text-xs text-white placeholder-ink-500 focus:outline-none focus:border-ink-500"
                  />
                </div>
              </div>

              {/* Quick preset paths */}
              <div className="flex flex-wrap items-center gap-2 text-xs text-ink-400">
                <span className="text-ink-500 font-mono">Quick paths:</span>
                <button
                  type="button"
                  onClick={() => {
                    setRepoPath(".");
                    setRepoName("entropy-workspace");
                  }}
                  className="bg-ink-850 hover:bg-ink-800 text-ink-300 px-2 py-0.5 rounded border border-border font-mono text-[11px] transition-colors"
                >
                  . (workspace)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setRepoPath("./backend/tests/fixtures/clean_python_project");
                    setRepoName("clean-python-project");
                  }}
                  className="bg-ink-850 hover:bg-ink-800 text-ink-300 px-2 py-0.5 rounded border border-border font-mono text-[11px] transition-colors"
                >
                  clean_python_project
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setRepoPath("./backend/tests/fixtures/mixed_language_project");
                    setRepoName("mixed-language-project");
                  }}
                  className="bg-ink-850 hover:bg-ink-800 text-ink-300 px-2 py-0.5 rounded border border-border font-mono text-[11px] transition-colors"
                >
                  mixed_language_project
                </button>
              </div>

              <div className="pt-2 flex items-center justify-between border-t border-border">
                <div className="text-[11px] text-ink-500 font-mono">
                  Limits: 2MB/file • 50,000 files max • Static AST only
                </div>

                <button
                  type="submit"
                  disabled={isScanning || !repoPath.trim()}
                  className="flex items-center gap-2 bg-ink-100 hover:bg-white text-ink-950 disabled:opacity-50 font-medium px-4 py-1.5 rounded-md text-xs transition-colors cursor-pointer"
                >
                  {isScanning ? (
                    <>
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      <span>{SCAN_STEPS[scanStepIndex]}</span>
                    </>
                  ) : (
                    <>
                      <FolderGit2 className="h-3.5 w-3.5" />
                      <span>Start scan</span>
                    </>
                  )}
                </button>
              </div>
            </form>

            {/* Scan Progress State */}
            {isScanning && (
              <div className="p-3.5 rounded-md bg-ink-850 border border-border font-mono text-xs space-y-2">
                <div className="flex items-center gap-2 text-ink-200">
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-ink-400" />
                  <span>{SCAN_STEPS[scanStepIndex]}</span>
                </div>
                <div className="w-full bg-ink-800 h-1 rounded-full overflow-hidden">
                  <div
                    className="bg-emerald-400 h-full transition-all duration-300"
                    style={{ width: `${((scanStepIndex + 1) / SCAN_STEPS.length) * 100}%` }}
                  />
                </div>
              </div>
            )}

            {/* Error notification */}
            {error && (
              <div className="p-3 rounded-md bg-ink-850 border border-border text-xs flex items-start gap-2.5">
                <AlertCircle className="h-4 w-4 text-red-400 mt-0.5 shrink-0" />
                <div>
                  <p className="font-medium text-red-300">Scan failed</p>
                  <p className="mt-0.5 font-mono text-[11px] text-ink-400">{error}</p>
                </div>
              </div>
            )}
          </div>

          {/* Real Scan Results */}
          {manifest && activeScan ? (
            <div className="space-y-6">
              {/* Navigation Sub-Tabs */}
              <div className="flex items-center gap-1.5 border-b border-border pb-3">
                <button
                  onClick={() => setActiveTab("overview")}
                  className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                    activeTab === "overview"
                      ? "bg-ink-800 text-white border border-border"
                      : "text-ink-400 hover:text-white"
                  }`}
                >
                  <FolderGit2 className="w-3.5 h-3.5" />
                  <span>Overview</span>
                </button>

                <button
                  onClick={() => {
                    setActiveTab("history");
                    if (activeScan?.repository?.repository_id) {
                      loadHistoryAndTrend(activeScan.repository.repository_id);
                    }
                  }}
                  className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                    activeTab === "history"
                      ? "bg-ink-800 text-white border border-border"
                      : "text-ink-400 hover:text-white"
                  }`}
                >
                  <History className="w-3.5 h-3.5" />
                  <span>Scan history &amp; trends</span>
                  {history && history.total > 0 && (
                    <span className="ml-1 px-1.5 py-0.2 rounded text-[10px] bg-ink-900 font-mono text-ink-300">
                      {history.total}
                    </span>
                  )}
                </button>

                <button
                  onClick={() => setActiveTab("comparison")}
                  className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                    activeTab === "comparison"
                      ? "bg-ink-800 text-white border border-border"
                      : "text-ink-400 hover:text-white"
                  }`}
                >
                  <GitCompare className="w-3.5 h-3.5" />
                  <span>Compare scans</span>
                  {comparison && (
                    <span className="ml-1 px-1.5 py-0.2 rounded text-[10px] bg-ink-900 font-mono text-emerald-400">
                      active
                    </span>
                  )}
                </button>
              </div>

              {activeTab === "overview" && (
                <div className="space-y-6">
                  {/* Entropy Debt Score Banner */}
                  {score && (
                    <ScoreBanner
                      score={score}
                      repository={activeScan?.repository}
                      durationMs={activeScan?.duration_ms}
                    />
                  )}

                  {/* Architectural Debt Categories Breakdown */}
                  {score && score.category_scores && (
                    <CategoryMatrix
                      categories={score.category_scores}
                      coverage={score.coverage}
                      selectedCategory={selectedCategory}
                      onSelectCategory={setSelectedCategory}
                    />
                  )}

                  {/* Debt Findings */}
                  <FindingsViewer
                    scanId={activeScan?.scan_id || ""}
                    findings={findings}
                    selectedCategory={selectedCategory}
                    isLoading={isLoadingFindings}
                  />

                  {/* Summary Stat Grid */}
                  <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
                    <div className="bg-card border border-border rounded-lg p-3.5">
                      <span className="text-[11px] text-ink-400 flex items-center gap-1.5 font-medium">
                        <Files className="h-3 w-3 text-ink-400" />
                        Total files
                      </span>
                      <p className="text-xl font-semibold text-white mt-1 font-mono tabular-nums">
                        {manifest.repository.total_files}
                      </p>
                      <span className="text-[10px] text-ink-500 font-mono">Inspected</span>
                    </div>

                    <div className="bg-card border border-border rounded-lg p-3.5">
                      <span className="text-[11px] text-ink-400 flex items-center gap-1.5 font-medium">
                        <FileCode className="h-3 w-3 text-ink-400" />
                        Source files
                      </span>
                      <p className="text-xl font-semibold text-white mt-1 font-mono tabular-nums">
                        {manifest.repository.source_files}
                      </p>
                      <span className="text-[10px] text-ink-500 font-mono">Recognized</span>
                    </div>

                    <div className="bg-card border border-border rounded-lg p-3.5">
                      <span className="text-[11px] text-ink-400 flex items-center gap-1.5 font-medium">
                        <EyeOff className="h-3 w-3 text-ink-400" />
                        Ignored
                      </span>
                      <p className="text-xl font-semibold text-white mt-1 font-mono tabular-nums">
                        {manifest.repository.ignored_files}
                      </p>
                      <span className="text-[10px] text-ink-500 font-mono">.gitignore</span>
                    </div>

                    <div className="bg-card border border-border rounded-lg p-3.5">
                      <span className="text-[11px] text-ink-400 flex items-center gap-1.5 font-medium">
                        <FileWarning className="h-3 w-3 text-ink-400" />
                        Skipped files
                      </span>
                      <p className="text-xl font-semibold text-white mt-1 font-mono tabular-nums">
                        {manifest.repository.skipped_files}
                      </p>
                      <span className="text-[10px] text-ink-500 font-mono">Binary or size</span>
                    </div>

                    <div className="bg-card border border-border rounded-lg p-3.5">
                      <span className="text-[11px] text-ink-400 flex items-center gap-1.5 font-medium">
                        <Code2 className="h-3 w-3 text-ink-400" />
                        Total LOC
                      </span>
                      <p className="text-xl font-semibold text-white mt-1 font-mono tabular-nums">
                        {manifest.repository.total_source_loc.toLocaleString()}
                      </p>
                      <span className="text-[10px] text-ink-500 font-mono">Lines of code</span>
                    </div>

                    <div className="bg-card border border-border rounded-lg p-3.5">
                      <span className="text-[11px] text-ink-400 flex items-center gap-1.5 font-medium">
                        <FileText className="h-3 w-3 text-ink-400" />
                        Source size
                      </span>
                      <p className="text-xl font-semibold text-white mt-1 font-mono tabular-nums">
                        {(manifest.repository.total_source_size / 1024).toFixed(1)} <span className="text-xs text-ink-400 font-normal">KB</span>
                      </p>
                      <span className="text-[10px] text-ink-500 font-mono">Uncompressed</span>
                    </div>
                  </div>

                  {/* Languages Breakdown */}
                  <div className="bg-card border border-border rounded-xl p-5 space-y-3">
                    <h3 className="text-xs font-medium text-ink-200 uppercase tracking-wider flex items-center gap-2">
                      <Code2 className="h-3.5 w-3.5 text-ink-400" />
                      <span>Languages detected</span>
                    </h3>

                    {Object.keys(manifest.languages).length === 0 ? (
                      <p className="text-xs text-ink-500 font-mono">No recognized languages detected</p>
                    ) : (
                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                        {Object.entries(manifest.languages).map(([lang, count]) => {
                          const isSupported = lang.toLowerCase() === "python";
                          return (
                            <div
                              key={lang}
                              className="p-3 rounded-lg bg-ink-850 border border-border flex items-center justify-between"
                            >
                              <div>
                                <div className="flex items-center gap-2">
                                  <span className="font-medium text-xs text-white capitalize">{lang}</span>
                                  <span className="text-[11px] font-mono text-ink-300 bg-ink-800 border border-border px-1.5 py-0.5 rounded tabular-nums">
                                    {count}
                                  </span>
                                </div>
                                <div className="mt-1">
                                  {isSupported ? (
                                    <span className="text-[11px] text-emerald-400 font-mono">
                                      Analyzer available
                                    </span>
                                  ) : (
                                    <span className="text-[11px] text-ink-500 font-mono">
                                      Scanner only
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

                  {/* Source Files Explorer */}
                  <div className="bg-card border border-border rounded-xl p-5 space-y-3">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div>
                        <h3 className="text-xs font-medium text-ink-200 uppercase tracking-wider flex items-center gap-2">
                          <FolderTree className="h-3.5 w-3.5 text-ink-400" />
                          <span>Discovered source files</span>
                        </h3>
                        <p className="text-xs text-ink-400 mt-0.5">
                          Showing {filteredFiles.length} of {manifest.files.length} source files
                        </p>
                      </div>

                      {/* Filters */}
                      <div className="flex items-center gap-2">
                        <div className="relative">
                          <Search className="h-3 w-3 text-ink-500 absolute left-2.5 top-2.5 pointer-events-none" />
                          <input
                            type="text"
                            placeholder="Search file path"
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="bg-ink-850 border border-border rounded-md pl-7 pr-3 py-1.5 text-xs text-white placeholder-ink-500 font-mono focus:outline-none focus:border-ink-500 w-44 sm:w-56"
                          />
                        </div>

                        <select
                          value={selectedLanguageFilter}
                          onChange={(e) => setSelectedLanguageFilter(e.target.value)}
                          className="bg-ink-850 border border-border text-xs text-ink-200 rounded-md px-2.5 py-1.5 focus:outline-none focus:border-ink-500 cursor-pointer capitalize"
                        >
                          <option value="ALL">All languages</option>
                          {Object.keys(manifest.languages).map((l) => (
                            <option key={l} value={l}>
                              {l}
                            </option>
                          ))}
                        </select>
                      </div>
                    </div>

                    <div className="border border-border rounded-lg overflow-x-auto">
                      <table className="w-full text-left text-xs">
                        <thead className="bg-ink-850 text-ink-400 font-mono text-[11px] border-b border-border">
                          <tr>
                            <th className="px-4 py-2 font-normal">Relative path</th>
                            <th className="px-4 py-2 font-normal">Language</th>
                            <th className="px-4 py-2 font-normal">Size</th>
                            <th className="px-4 py-2 font-normal">Lines</th>
                            <th className="px-4 py-2 font-normal">Analysis status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border font-mono text-xs">
                          {filteredFiles.length === 0 ? (
                            <tr>
                              <td colSpan={5} className="px-4 py-8 text-center text-ink-500">
                                No source files match the filter
                              </td>
                            </tr>
                          ) : (
                            filteredFiles.map((f, idx) => (
                              <tr key={idx} className="hover:bg-ink-850/50 transition-colors">
                                <td className="px-4 py-2 text-ink-100">{f.path}</td>
                                <td className="px-4 py-2">
                                  <span className="px-1.5 py-0.5 rounded text-[11px] bg-ink-800 border border-border text-ink-300 capitalize">
                                    {f.language}
                                  </span>
                                </td>
                                <td className="px-4 py-2 text-ink-400 tabular-nums">
                                  {f.size > 1024 ? `${(f.size / 1024).toFixed(1)} KB` : `${f.size} B`}
                                </td>
                                <td className="px-4 py-2 text-ink-400 tabular-nums">{f.line_count ?? "—"}</td>
                                <td className="px-4 py-2">
                                  {f.analysis_supported ? (
                                    <span className="text-[11px] text-emerald-400 font-mono">
                                      Supported
                                    </span>
                                  ) : (
                                    <span className="text-[11px] text-ink-500 font-mono">
                                      {f.skip_reason || "Scanner only"}
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

                  {/* Skipped Files Table */}
                  {manifest.skipped_files && manifest.skipped_files.length > 0 && (
                    <div className="bg-card border border-border rounded-xl p-5 space-y-3">
                      <div>
                        <h3 className="text-xs font-medium text-ink-200 uppercase tracking-wider flex items-center gap-2">
                          <FileWarning className="h-3.5 w-3.5 text-amber-400" />
                          <span>Skipped files ({manifest.skipped_files.length})</span>
                        </h3>
                        <p className="text-xs text-ink-400 mt-0.5">
                          Files safely excluded during ingestion due to size limits or binary encoding
                        </p>
                      </div>

                      <div className="border border-border rounded-lg overflow-x-auto">
                        <table className="w-full text-left text-xs">
                          <thead className="bg-ink-850 text-ink-400 font-mono text-[11px] border-b border-border">
                            <tr>
                              <th className="px-4 py-2 font-normal">File path</th>
                              <th className="px-4 py-2 font-normal">Size</th>
                              <th className="px-4 py-2 font-normal">Skip reason</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border font-mono text-xs">
                            {manifest.skipped_files.map((sf, idx) => (
                              <tr key={idx} className="hover:bg-ink-850/50">
                                <td className="px-4 py-2 text-ink-200">{sf.path}</td>
                                <td className="px-4 py-2 text-ink-400 tabular-nums">
                                  {sf.size > 1024 ? `${(sf.size / 1024).toFixed(1)} KB` : `${sf.size} B`}
                                </td>
                                <td className="px-4 py-2 text-ink-400 text-[11px]">{sf.reason}</td>
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
                      className="w-full flex items-center justify-between text-xs text-ink-300 hover:text-white transition-colors"
                    >
                      <div className="flex items-center gap-2">
                        <Braces className="h-3.5 w-3.5 text-ink-400" />
                        <span>Manifest payload JSON</span>
                        <span className="text-[11px] text-ink-400 font-mono">
                          GET /scans/{activeScan?.scan_id}/manifest
                        </span>
                      </div>
                      <span className="text-ink-500 font-mono">{showJsonManifest ? "Hide JSON" : "View JSON"}</span>
                    </button>

                    {showJsonManifest && (
                      <div className="mt-3 pt-3 border-t border-border">
                        <pre className="bg-ink-950 p-4 rounded-md border border-border text-[11px] font-mono text-ink-200 overflow-x-auto max-h-96">
                          {JSON.stringify(manifest, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Scan History Tab */}
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
                      if (activeScan?.repository?.repository_id) {
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
                    <div className="bg-card border border-border rounded-xl p-12 flex flex-col items-center justify-center min-h-[300px] text-center space-y-2">
                      <Loader2 className="w-6 h-6 text-ink-300 animate-spin" />
                      <p className="text-xs font-medium text-ink-200">
                        Computing comparison...
                      </p>
                      <p className="text-[11px] text-ink-500 font-mono">
                        Matching fingerprints and calculating deltas
                      </p>
                    </div>
                  ) : comparisonError ? (
                    <div className="bg-card border border-border rounded-xl p-5 text-xs text-red-300 space-y-1">
                      <div className="flex items-center gap-2 font-medium">
                        <AlertCircle className="w-4 h-4 text-red-400" />
                        <span>Comparison failed</span>
                      </div>
                      <p className="font-mono text-ink-400">{comparisonError}</p>
                    </div>
                  ) : comparison ? (
                    <ScanComparisonView
                      comparison={comparison}
                      onClose={() => setActiveTab("history")}
                    />
                  ) : (
                    <div className="bg-card border border-border rounded-xl p-10 text-center space-y-3">
                      <GitCompare className="w-8 h-8 text-ink-500 mx-auto" />
                      <div className="space-y-0.5">
                        <h3 className="text-xs font-medium text-white">No active comparison</h3>
                        <p className="text-xs text-ink-400 max-w-sm mx-auto">
                          Select two scans from history to inspect score deltas
                        </p>
                      </div>
                      <button
                        onClick={() => setActiveTab("history")}
                        className="px-3.5 py-1.5 rounded-md bg-ink-800 hover:bg-ink-700 text-white text-xs font-medium border border-border transition-colors"
                      >
                        Open history
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            /* Empty Welcome State */
            <div className="border border-dashed border-border rounded-xl p-12 text-center bg-card">
              <div className="h-10 w-10 rounded-lg bg-ink-800 border border-border text-ink-300 flex items-center justify-center mx-auto mb-3">
                <FolderGit2 className="h-5 w-5" />
              </div>
              <h2 className="text-sm font-medium text-white tracking-tight">No repository loaded</h2>
              <p className="text-xs text-ink-400 max-w-md mx-auto mt-1 leading-relaxed">
                Enter a local code repository path or remote URL above and click <strong>Start scan</strong> to analyze architectural debt
              </p>
            </div>
          )}
        </>
      )}
    </div>
  );
}

"use client";

import { useEffect, useState, useRef } from "react";
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
  uploadAndScanArchive,
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
import { motion, AnimatePresence } from "framer-motion";
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
  ChevronUp,
  Terminal,
  FileText,
  Braces,
  History,
  GitCompare,
  GitPullRequest,
  AlertCircle,
  Loader2,
  Sparkles,
  Layers,
  CheckCircle2,
  ArrowRight,
  Shield,
  Play,
  RotateCcw,
  UploadCloud,
  FolderUp,
  FileArchive,
  X,
  HardDrive,
} from "lucide-react";

function formatBytes(bytes: number, decimals = 1): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
}

async function packageFilesToZip(
  files: File[],
  onProgress?: (msg: string) => void
): Promise<Blob> {
  const JSZip = (await import("jszip")).default;
  const zip = new JSZip();

  const ignoredPatterns = [
    /(^|\/)\.git\//,
    /(^|\/)node_modules\//,
    /(^|\/)__pycache__\//,
    /(^|\/)\.venv\//,
    /(^|\/)venv\//,
    /(^|\/)\.next\//,
    /(^|\/)dist\//,
    /(^|\/)build\//,
    /(^|\/)\.turbo\//,
    /(^|\/)\.idea\//,
    /(^|\/)\.vscode\//,
    /(^|\/)\.DS_Store$/,
  ];

  let addedCount = 0;
  for (const file of files) {
    const relativePath = file.webkitRelativePath || file.name;
    const isIgnored = ignoredPatterns.some((pattern) => pattern.test(relativePath));
    if (isIgnored) continue;

    zip.file(relativePath, file);
    addedCount++;
  }

  if (addedCount === 0) {
    throw new Error("No valid source files found in the selected folder.");
  }

  onProgress?.("Compressing archive...");
  return await zip.generateAsync({
    type: "blob",
    compression: "DEFLATE",
    compressionOptions: { level: 6 },
  });
}

async function getFilesFromDataTransfer(items: DataTransferItemList): Promise<File[]> {
  const files: File[] = [];

  async function traverseEntry(entry: any, path = ""): Promise<void> {
    if (!entry) return;
    if (entry.isFile) {
      await new Promise<void>((resolve) => {
        entry.file(
          (file: File) => {
            Object.defineProperty(file, "webkitRelativePath", {
              value: path ? `${path}/${file.name}` : file.name,
              writable: true,
            });
            files.push(file);
            resolve();
          },
          () => resolve()
        );
      });
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      const readEntries = (): Promise<any[]> =>
        new Promise((resolve) => {
          reader.readEntries(
            (entries: any[]) => resolve(entries),
            () => resolve([])
          );
        });

      let entries = await readEntries();
      while (entries && entries.length > 0) {
        for (const child of entries) {
          const nextPath = path ? `${path}/${entry.name}` : entry.name;
          await traverseEntry(child, nextPath);
        }
        entries = await readEntries();
      }
    }
  }

  const entries: any[] = [];
  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    if (item.webkitGetAsEntry) {
      const entry = item.webkitGetAsEntry();
      if (entry) entries.push(entry);
    } else {
      const file = item.getAsFile();
      if (file) files.push(file);
    }
  }

  for (const entry of entries) {
    await traverseEntry(entry);
  }

  return files;
}

const SCAN_STEPS = [
  "Inspecting repository structure...",
  "Discovering source files...",
  "Parsing AST syntax trees...",
  "Analyzing debt rules & scoring...",
  "Scan complete",
];

export default function RepositoryIngestionDashboard() {
  const [scanMode, setScanMode] = useState<"folder" | "path">("folder");
  const [repoPath, setRepoPath] = useState("");
  const [repoName, setRepoName] = useState("");
  const [selectedFolderFiles, setSelectedFolderFiles] = useState<File[]>([]);
  const [selectedZipFile, setSelectedZipFile] = useState<File | null>(null);
  const [folderDisplayName, setFolderDisplayName] = useState<string>("");
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [isWindowDragging, setIsWindowDragging] = useState<boolean>(false);
  const dragCounter = useRef<number>(0);
  const [packagingMessage, setPackagingMessage] = useState<string>("");

  const folderInputRef = useRef<HTMLInputElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const zipInputRef = useRef<HTMLInputElement>(null);

  const totalFolderSize = selectedZipFile
    ? selectedZipFile.size
    : selectedFolderFiles.reduce((acc, f) => acc + f.size, 0);

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

  const handleStartScanClick = () => {
    setActiveTab("overview");
    const el = document.getElementById("scan-trigger-box");
    if (el) {
      el.scrollIntoView({ behavior: "smooth" });
      const input = el.querySelector("input");
      if (input) input.focus();
    }
  };

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
          "Cannot reach backend API. Ensure your backend service is running (e.g. uvicorn app.main:app on port 8000).";
      } else if (
        errorMessage.toLowerCase().includes("path is outside the allowed") ||
        errorMessage.toLowerCase().includes("directory does not exist") ||
        errorMessage.toLowerCase().includes("repository not found")
      ) {
        errorMessage = `${errorMessage}. Tip: To scan code from your local machine via the browser, use the "Local Files / Folder" tab above to choose your folder or upload a ZIP directly.`;
      }
      setError(errorMessage);
    } finally {
      setIsScanning(false);
    }
  };

  const handleFolderSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || e.target.files.length === 0) return;
    const fileList = Array.from(e.target.files);
    setSelectedFolderFiles(fileList);
    setSelectedZipFile(null);
    setError(null);

    const firstPath = fileList[0].webkitRelativePath;
    const detectedName = firstPath ? firstPath.split("/")[0] : "local-project";
    setFolderDisplayName(detectedName);
    if (!repoName.trim()) {
      setRepoName(detectedName);
    }
  };

  const handleZipSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || e.target.files.length === 0) return;
    const file = e.target.files[0];
    setSelectedZipFile(file);
    setSelectedFolderFiles([]);
    setError(null);

    const detectedName = file.name.replace(/\.zip$/i, "");
    setFolderDisplayName(detectedName);
    if (!repoName.trim()) {
      setRepoName(detectedName);
    }
  };

  const processDroppedData = async (dataTransfer: DataTransfer) => {
    setError(null);
    setScanMode("folder");

    if (!dataTransfer.files || dataTransfer.files.length === 0) return;

    // 1. Single .zip file dropped
    if (
      dataTransfer.files.length === 1 &&
      dataTransfer.files[0].name.toLowerCase().endsWith(".zip")
    ) {
      const file = dataTransfer.files[0];
      setSelectedZipFile(file);
      setSelectedFolderFiles([]);
      const detectedName = file.name.replace(/\.zip$/i, "");
      setFolderDisplayName(detectedName);
      if (!repoName.trim()) setRepoName(detectedName);
      return;
    }

    // 2. Folder items via DataTransferItemList traversal
    if (dataTransfer.items && dataTransfer.items.length > 0) {
      try {
        const files = await getFilesFromDataTransfer(dataTransfer.items);
        if (files.length > 0) {
          setSelectedFolderFiles(files);
          setSelectedZipFile(null);
          const firstPath = files[0].webkitRelativePath || files[0].name;
          const detectedName = firstPath.includes("/")
            ? firstPath.split("/")[0]
            : files.length === 1
            ? files[0].name.replace(/\.[^/.]+$/, "")
            : "local-files";
          setFolderDisplayName(detectedName);
          if (!repoName.trim()) setRepoName(detectedName);
          return;
        }
      } catch (err) {
        console.warn("Folder item traversal fallback:", err);
      }
    }

    // 3. Fallback to flat files list
    const files = Array.from(dataTransfer.files);
    if (files.length > 0) {
      setSelectedFolderFiles(files);
      setSelectedZipFile(null);
      const detectedName =
        files.length === 1
          ? files[0].name.replace(/\.[^/.]+$/, "")
          : "local-files";
      setFolderDisplayName(detectedName);
      if (!repoName.trim()) setRepoName(detectedName);
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      await processDroppedData(e.dataTransfer);
    }
  };

  const handleIndividualFilesSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || e.target.files.length === 0) return;
    const fileList = Array.from(e.target.files);
    setSelectedFolderFiles(fileList);
    setSelectedZipFile(null);
    setError(null);

    const detectedName =
      fileList.length === 1
        ? fileList[0].name.replace(/\.[^/.]+$/, "")
        : "local-files";
    setFolderDisplayName(detectedName);
    if (!repoName.trim()) {
      setRepoName(detectedName);
    }
  };

  const processDroppedDataRef = useRef(processDroppedData);
  processDroppedDataRef.current = processDroppedData;

  // Window-level drag and drop listener so users can drop anywhere onto the website
  useEffect(() => {
    const handleDragEnter = (e: DragEvent) => {
      e.preventDefault();
      dragCounter.current += 1;
      if (e.dataTransfer && e.dataTransfer.types.includes("Files")) {
        setIsWindowDragging(true);
      }
    };

    const handleDragLeave = (e: DragEvent) => {
      e.preventDefault();
      dragCounter.current -= 1;
      if (dragCounter.current <= 0) {
        setIsWindowDragging(false);
        dragCounter.current = 0;
      }
    };

    const handleDragOver = (e: DragEvent) => {
      e.preventDefault();
      if (e.dataTransfer) {
        e.dataTransfer.dropEffect = "copy";
      }
    };

    const handleGlobalDrop = async (e: DragEvent) => {
      e.preventDefault();
      dragCounter.current = 0;
      setIsWindowDragging(false);
      setIsDragging(false);
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        await processDroppedDataRef.current(e.dataTransfer);
        const el = document.getElementById("scan-trigger-box");
        if (el) el.scrollIntoView({ behavior: "smooth" });
      }
    };

    window.addEventListener("dragenter", handleDragEnter);
    window.addEventListener("dragleave", handleDragLeave);
    window.addEventListener("dragover", handleDragOver);
    window.addEventListener("drop", handleGlobalDrop);

    return () => {
      window.removeEventListener("dragenter", handleDragEnter);
      window.removeEventListener("dragleave", handleDragLeave);
      window.removeEventListener("dragover", handleDragOver);
      window.removeEventListener("drop", handleGlobalDrop);
    };
  }, []);

  const handleStartFolderScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedZipFile && selectedFolderFiles.length === 0) {
      setError("Please select a local folder or .ZIP archive to scan.");
      return;
    }

    setError(null);
    setIsScanning(true);
    setScanStepIndex(0);

    const interval = setInterval(() => {
      setScanStepIndex((prev) => (prev < 3 ? prev + 1 : prev));
    }, 450);

    try {
      let result: RepositoryScanResult;
      const targetName = repoName.trim() || folderDisplayName.trim() || undefined;

      if (selectedZipFile) {
        setPackagingMessage("Uploading archive to Entropy scanner...");
        result = await uploadAndScanArchive(
          selectedZipFile,
          selectedZipFile.name,
          targetName
        );
      } else {
        setPackagingMessage("Packaging and filtering local source files...");
        const zipBlob = await packageFilesToZip(selectedFolderFiles, (msg) => {
          setPackagingMessage(msg);
        });
        setPackagingMessage("Analyzing AST topology & rules...");
        result = await uploadAndScanArchive(
          zipBlob,
          `${folderDisplayName || "local-project"}.zip`,
          targetName
        );
      }

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

      setTimeout(() => {
        const el = document.getElementById("scan-results-view");
        if (el) el.scrollIntoView({ behavior: "smooth" });
      }, 150);
    } catch (err: unknown) {
      clearInterval(interval);
      let errorMessage = err instanceof Error ? err.message : "Failed to scan local repository files";
      if (
        errorMessage.toLowerCase().includes("failed to fetch") ||
        errorMessage.toLowerCase().includes("networkerror")
      ) {
        errorMessage = "Cannot reach backend API. Ensure your backend service is running.";
      }
      setError(errorMessage);
    } finally {
      setIsScanning(false);
      setPackagingMessage("");
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
    <div className="space-y-8 relative">
      {/* Global Drag and Drop Overlay */}
      <AnimatePresence>
        {isWindowDragging && (
          <motion.div
            initial={{ opacity: 0, scale: 0.98 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.98 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 z-[100] flex items-center justify-center bg-ink-950/90 backdrop-blur-md p-6 pointer-events-none"
          >
            <div className="w-full max-w-xl p-10 rounded-3xl border-2 border-dashed border-red-500 bg-red-950/40 flex flex-col items-center justify-center text-center space-y-5 shadow-glow-red">
              <div className="h-20 w-20 rounded-3xl bg-red-500/20 border border-red-500/40 flex items-center justify-center text-red-400 animate-bounce">
                <UploadCloud className="h-10 w-10 text-red-400" />
              </div>
              <div className="space-y-2">
                <h3 className="text-2xl font-bold text-white tracking-tight">
                  Drop Local Files or Folder Here
                </h3>
                <p className="text-sm text-red-200/80 max-w-md mx-auto leading-relaxed">
                  Release anywhere to package and scan your project hermetically in your browser.
                </p>
              </div>
              <div className="flex flex-wrap items-center justify-center gap-2.5 text-xs font-mono text-red-300 bg-red-950/80 border border-red-500/40 px-4 py-2 rounded-full">
                <span>📁 Folders</span>
                <span className="text-red-600">•</span>
                <span>📄 Source Files (.py, .ts, .js)</span>
                <span className="text-red-600">•</span>
                <span>📦 .ZIP Archives</span>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
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
              <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
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
          className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer ${
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
          className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer ${
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
          <div id="scan-trigger-box" className="glass-panel border border-border/90 rounded-2xl p-6 space-y-5 shadow-2xl relative overflow-hidden">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border/80 pb-4">
              <div>
                <h2 className="text-xs font-medium text-red-400 uppercase tracking-wider flex items-center gap-2">
                  <Terminal className="h-3.5 w-3.5 text-red-400" />
                  <span>Scan repository</span>
                </h2>
                <p className="text-xs text-ink-300 mt-1">
                  Choose a local directory, upload a ZIP archive, or provide a Git URL. Zero untrusted code execution.
                </p>
              </div>

              {/* Mode Toggle Pills */}
              <div className="flex items-center bg-ink-950/80 border border-border/80 rounded-xl p-1 gap-1 self-start sm:self-auto">
                <button
                  type="button"
                  onClick={() => setScanMode("folder")}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                    scanMode === "folder"
                      ? "bg-red-500/15 text-red-400 border border-red-500/30 shadow-sm"
                      : "text-ink-400 hover:text-white"
                  }`}
                >
                  <FolderUp className="w-3.5 h-3.5" />
                  <span>Local Files / Folder</span>
                </button>
                <button
                  type="button"
                  onClick={() => setScanMode("path")}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                    scanMode === "path"
                      ? "bg-red-500/15 text-red-400 border border-red-500/30 shadow-sm"
                      : "text-ink-400 hover:text-white"
                  }`}
                >
                  <Code2 className="w-3.5 h-3.5" />
                  <span>Path / Git URL</span>
                </button>
              </div>
            </div>

            {scanMode === "folder" ? (
              <div className="space-y-4">
                <input
                  type="file"
                  ref={folderInputRef}
                  {...({ webkitdirectory: "", directory: "" } as any)}
                  multiple
                  onChange={handleFolderSelect}
                  className="hidden"
                />
                <input
                  type="file"
                  ref={fileInputRef}
                  multiple
                  onChange={handleIndividualFilesSelect}
                  className="hidden"
                />
                <input
                  type="file"
                  ref={zipInputRef}
                  accept=".zip"
                  onChange={handleZipSelect}
                  className="hidden"
                />

                {!selectedZipFile && selectedFolderFiles.length === 0 ? (
                  <div
                    onDragOver={(e) => {
                      e.preventDefault();
                      setIsDragging(true);
                    }}
                    onDragLeave={() => setIsDragging(false)}
                    onDrop={handleDrop}
                    className={`border-2 border-dashed rounded-2xl p-8 text-center transition-all duration-200 ${
                      isDragging || isWindowDragging
                        ? "border-red-400 bg-red-500/15 shadow-glow-red"
                        : "border-border/80 bg-ink-950/40 hover:border-red-500/40 hover:bg-ink-950/60"
                    }`}
                  >
                    <div className="flex flex-col items-center justify-center space-y-4">
                      <div className="h-14 w-14 rounded-2xl bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400 shadow-glow-red">
                        <FolderUp className="h-7 w-7" />
                      </div>
                      <div>
                        <h3 className="text-sm font-semibold text-white">
                          Drag &amp; Drop Local Folder or Files Here
                        </h3>
                        <p className="text-xs text-ink-400 mt-1 max-w-md mx-auto leading-relaxed">
                          Drop any local project directory, source code files (<code className="text-red-400">.py</code>, <code className="text-red-400">.ts</code>, <code className="text-red-400">.js</code>), or <code className="text-red-400">.zip</code> archive. Packaged hermetically in your browser.
                        </p>
                      </div>

                      <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
                        <button
                          type="button"
                          onClick={() => folderInputRef.current?.click()}
                          className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-red-600 hover:bg-red-500 text-ink-950 font-bold text-xs shadow-glow-red transition-all cursor-pointer"
                        >
                          <FolderUp className="h-4 w-4" />
                          <span>Choose Local Folder</span>
                        </button>

                        <button
                          type="button"
                          onClick={() => fileInputRef.current?.click()}
                          className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-ink-850 hover:bg-ink-800 text-ink-200 border border-border text-xs font-medium transition-all cursor-pointer"
                        >
                          <FileCode className="h-4 w-4 text-red-400" />
                          <span>Choose Files</span>
                        </button>

                        <button
                          type="button"
                          onClick={() => zipInputRef.current?.click()}
                          className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-ink-850 hover:bg-ink-800 text-ink-200 border border-border text-xs font-medium transition-all cursor-pointer"
                        >
                          <FileArchive className="h-4 w-4 text-ink-400" />
                          <span>Upload .ZIP Archive</span>
                        </button>
                      </div>

                      <div className="text-[11px] font-mono text-ink-500 pt-1">
                        Drop anywhere on the screen or use buttons above • Zero code execution
                      </div>
                    </div>
                  </div>
                ) : (
                  <form
                    onSubmit={handleStartFolderScan}
                    onDragOver={(e) => {
                      e.preventDefault();
                      setIsDragging(true);
                    }}
                    onDragLeave={() => setIsDragging(false)}
                    onDrop={handleDrop}
                    className="space-y-4"
                  >
                    <div className="p-4 rounded-xl bg-ink-900/80 border border-red-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                      <div className="flex items-center gap-3.5">
                        <div className="h-10 w-10 rounded-xl bg-red-500/15 border border-red-500/40 flex items-center justify-center text-red-400 shrink-0">
                          {selectedZipFile ? (
                            <FileArchive className="h-5 w-5" />
                          ) : selectedFolderFiles.some((f) => f.webkitRelativePath?.includes("/")) ? (
                            <FolderGit2 className="h-5 w-5" />
                          ) : (
                            <FileCode className="h-5 w-5" />
                          )}
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-semibold text-white">
                              {folderDisplayName}
                            </span>
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-red-950/60 text-red-300 border border-red-500/30">
                              {selectedZipFile
                                ? "ZIP Archive"
                                : selectedFolderFiles.some((f) => f.webkitRelativePath?.includes("/"))
                                ? "Local Folder"
                                : "Source Files"}
                            </span>
                          </div>
                          <p className="text-xs text-ink-400 mt-0.5 font-mono">
                            {selectedZipFile
                              ? formatBytes(selectedZipFile.size)
                              : `${selectedFolderFiles.length} file(s) selected (${formatBytes(totalFolderSize)})`}
                          </p>
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto justify-end">
                        <button
                          type="button"
                          onClick={() => {
                            setSelectedFolderFiles([]);
                            setSelectedZipFile(null);
                            setFolderDisplayName("");
                          }}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-ink-400 hover:text-white hover:bg-ink-800 transition-colors cursor-pointer"
                        >
                          <X className="h-3.5 w-3.5" />
                          <span>Clear</span>
                        </button>

                        <button
                          type="button"
                          onClick={() => folderInputRef.current?.click()}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-ink-300 hover:text-white bg-ink-850 hover:bg-ink-800 border border-border transition-colors cursor-pointer"
                        >
                          <FolderUp className="h-3.5 w-3.5" />
                          <span>Folder</span>
                        </button>

                        <button
                          type="button"
                          onClick={() => fileInputRef.current?.click()}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-ink-300 hover:text-white bg-ink-850 hover:bg-ink-800 border border-border transition-colors cursor-pointer"
                        >
                          <FileCode className="h-3.5 w-3.5 text-red-400" />
                          <span>Files</span>
                        </button>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                      <div className="md:col-span-2">
                        <label className="block text-xs font-mono text-ink-300 mb-1.5">
                          Display name
                        </label>
                        <input
                          type="text"
                          placeholder="e.g. my-local-service"
                          value={repoName}
                          onChange={(e) => setRepoName(e.target.value)}
                          className="w-full bg-ink-950/80 border border-border rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-ink-500 focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500/40 transition-all font-mono"
                        />
                      </div>
                      <div className="flex items-end">
                        <button
                          type="submit"
                          disabled={isScanning}
                          className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-red-600 hover:bg-red-500 text-ink-950 font-bold text-xs shadow-glow-red transition-all disabled:opacity-50 cursor-pointer"
                        >
                          {isScanning ? (
                            <>
                              <Loader2 className="h-4 w-4 animate-spin" />
                              <span>Scanning local files...</span>
                            </>
                          ) : (
                            <>
                              <Play className="h-4 w-4 fill-ink-950" />
                              <span>Scan Local Files</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>
                  </form>
                )}
              </div>
            ) : (
              <form onSubmit={handleStartScan} className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div className="md:col-span-2">
                    <label className="block text-xs font-mono text-ink-300 mb-1.5">
                      Path or Git URL
                    </label>
                    <input
                      type="text"
                      placeholder="/path/to/project or https://github.com/owner/repo"
                      value={repoPath}
                      onChange={(e) => setRepoPath(e.target.value)}
                      required
                      className="w-full bg-ink-950/80 border border-border rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-ink-500 font-mono focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500/40 transition-all"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-mono text-ink-300 mb-1.5">
                      Display name (optional)
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. backend-api"
                      value={repoName}
                      onChange={(e) => setRepoName(e.target.value)}
                      className="w-full bg-ink-950/80 border border-border rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-ink-500 focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500/40 transition-all"
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
                    className="bg-ink-850 hover:bg-ink-800 text-ink-300 px-2 py-0.5 rounded border border-border font-mono text-[11px] transition-colors cursor-pointer"
                  >
                    . (workspace)
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setRepoPath("./backend/tests/fixtures/clean_python_project");
                      setRepoName("clean-python-project");
                    }}
                    className="bg-ink-850 hover:bg-ink-800 text-ink-300 px-2 py-0.5 rounded border border-border font-mono text-[11px] transition-colors cursor-pointer"
                  >
                    clean_python_project
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setRepoPath("./backend/tests/fixtures/mixed_language_project");
                      setRepoName("mixed-language-project");
                    }}
                    className="bg-ink-850 hover:bg-ink-800 text-ink-300 px-2 py-0.5 rounded border border-border font-mono text-[11px] transition-colors cursor-pointer"
                  >
                    mixed_language_project
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setRepoPath("https://github.com/expressjs/express");
                      setRepoName("express-sample");
                    }}
                    className="bg-ink-850 hover:bg-ink-800 text-ink-300 px-2 py-0.5 rounded border border-border font-mono text-[11px] transition-colors cursor-pointer"
                  >
                    express-sample (Git)
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
            )}

            {/* Scan Progress State */}
            {isScanning && (
              <div className="p-3.5 rounded-md bg-ink-850 border border-border font-mono text-xs space-y-2">
                <div className="flex items-center gap-2 text-ink-200">
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-ink-400" />
                  <span>{packagingMessage || SCAN_STEPS[scanStepIndex]}</span>
                </div>
                <div className="w-full bg-ink-800 h-1 rounded-full overflow-hidden">
                  <div
                    className="bg-red-500 h-full transition-all duration-300"
                    style={{ width: `${((scanStepIndex + 1) / SCAN_STEPS.length) * 100}%` }}
                  />
                </div>
              </div>
            )}

            {/* Error notification */}
            {error && (
              <div className="p-4 rounded-xl bg-red-950/30 border border-red-500/30 text-xs flex items-start gap-3">
                <AlertCircle className="h-4 w-4 text-red-400 mt-0.5 shrink-0" />
                <div className="flex-1 space-y-2">
                  <div className="flex items-center justify-between">
                    <p className="font-semibold text-red-300">Scan failed</p>
                    <button
                      type="button"
                      onClick={() => setError(null)}
                      className="text-[11px] text-ink-400 hover:text-white transition-colors"
                    >
                      Dismiss
                    </button>
                  </div>
                  <p className="font-mono text-xs text-ink-300 leading-relaxed whitespace-pre-wrap">{error}</p>
                  {scanMode === "path" && (
                    <div className="pt-2 border-t border-red-500/20 flex flex-wrap items-center justify-between gap-2">
                      <span className="text-[11px] text-ink-300">
                        Scanning code from your local machine?
                      </span>
                      <button
                        type="button"
                        onClick={() => {
                          setScanMode("folder");
                          setError(null);
                          setTimeout(() => folderInputRef.current?.click(), 150);
                        }}
                        className="px-3 py-1 rounded-lg bg-red-600 hover:bg-red-500 text-ink-950 text-xs font-semibold shadow-glow-red transition-all cursor-pointer"
                      >
                        Choose Local Folder
                      </button>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Real Scan Results */}
          {manifest && activeScan ? (
            <div id="scan-results-view" className="space-y-6 scroll-mt-20">
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
                    <span className="ml-1 px-1.5 py-0.2 rounded text-[10px] bg-ink-900 font-mono text-red-400">
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
                                    <span className="text-[11px] text-red-400 font-mono">
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
                                    <span className="text-[11px] text-red-400 font-mono">
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
            <div className="border border-border/80 rounded-2xl p-8 bg-ink-900/40 backdrop-blur-sm space-y-8">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2 text-red-400 text-xs font-mono font-medium">
                    <span className="relative flex h-2 w-2">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-500 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-red-600"></span>
                    </span>
                    <span>READY FOR FORENSIC SCANNING</span>
                  </div>
                  <h3 className="text-xl font-bold text-white tracking-tight">
                    Start a Scan or Explore the Interactive Sample Report
                  </h3>
                  <p className="text-xs text-ink-300 max-w-2xl leading-relaxed">
                    Test how Entropy analyzes cross-file AST trees, calculates mathematical debt deductions, and generates verified AI remediation without hallucinations.
                  </p>
                </div>

                <button
                  onClick={() => {
                    setScanMode("folder");
                    handleStartScanClick();
                    setTimeout(() => folderInputRef.current?.click(), 150);
                  }}
                  className="group flex items-center gap-2 px-5 py-3 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-ink-950 font-bold text-xs tracking-wide shadow-glow-emerald transition-all duration-200 self-start md:self-auto cursor-pointer"
                >
                  <FolderUp className="h-4 w-4 fill-ink-950" />
                  <span>Choose Folder or Drop Files</span>
                  <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
                </button>
              </div>

              {/* 3 Interactive Launch Modes */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div
                  onClick={() => {
                    setScanMode("folder");
                    handleStartScanClick();
                    setTimeout(() => folderInputRef.current?.click(), 250);
                  }}
                  className="p-5 rounded-xl bg-ink-900/70 border border-border/80 hover:border-emerald-500/50 hover:bg-ink-850/90 transition-all duration-200 cursor-pointer space-y-3 group"
                >
                  <div className="h-9 w-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 group-hover:scale-105 transition-transform">
                    <FolderUp className="h-4 w-4" />
                  </div>
                  <h4 className="text-sm font-semibold text-white group-hover:text-emerald-300 transition-colors">
                    1. Drag &amp; Drop / Local Files
                  </h4>
                  <p className="text-xs text-ink-400 leading-relaxed">
                    Drop any local folder, code files, or ZIP archive anywhere on screen. Fast in-browser packaging with zero untrusted code execution.
                  </p>
                  <div className="text-[11px] font-mono text-emerald-400 flex items-center gap-1">
                    <span>Drop or choose files</span>
                    <ArrowRight className="h-3 w-3" />
                  </div>
                </div>

                <div
                  onClick={() => {
                    setScanMode("path");
                    setRepoPath("https://github.com/expressjs/express");
                    setRepoName("express-sample");
                    handleStartScanClick();
                  }}
                  className="p-5 rounded-xl bg-ink-900/70 border border-border/80 hover:border-rose-500/50 hover:bg-ink-850/90 transition-all duration-200 cursor-pointer space-y-3 group"
                >
                  <div className="h-9 w-9 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 group-hover:scale-105 transition-transform">
                    <Code2 className="h-4 w-4" />
                  </div>
                  <h4 className="text-sm font-semibold text-white group-hover:text-rose-300 transition-colors">
                    2. Remote Git URL Scan
                  </h4>
                  <p className="text-xs text-ink-400 leading-relaxed">
                    Enter any public GitHub/GitLab URL. Entropy clones shallowly, audits the full topology, and generates scores.
                  </p>
                  <div className="text-[11px] font-mono text-rose-400 flex items-center gap-1">
                    <span>Try GitHub URL</span>
                    <ArrowRight className="h-3 w-3" />
                  </div>
                </div>

                <div
                  onClick={() => {
                    setScanMode("path");
                    setRepoPath("./backend/tests/fixtures/clean_python_project");
                    setRepoName("clean-python-project");
                    handleStartScanClick();
                  }}
                  className="p-5 rounded-xl bg-gradient-to-br from-emerald-950/30 to-ink-900/90 border border-emerald-500/40 hover:border-emerald-400 hover:shadow-glow-emerald transition-all duration-200 cursor-pointer space-y-3 group"
                >
                  <div className="h-9 w-9 rounded-lg bg-emerald-600/20 border border-emerald-500/50 flex items-center justify-center text-emerald-400 group-hover:scale-105 transition-transform">
                    <CheckCircle2 className="h-4 w-4" />
                  </div>
                  <h4 className="text-sm font-semibold text-white group-hover:text-emerald-300 transition-colors">
                    3. Clean Test Fixture
                  </h4>
                  <p className="text-xs text-ink-300 leading-relaxed">
                    Instantly inspect our zero-finding baseline test fixture. Fast deterministic AST analysis in under 20ms.
                  </p>
                  <div className="text-[11px] font-mono text-emerald-400 font-bold flex items-center gap-1">
                    <span>Scan test fixture</span>
                    <ArrowRight className="h-3 w-3" />
                  </div>
                </div>
              </div>

              {/* 5-Step Forensic Pipeline */}
              <div className="pt-6 border-t border-border/80 space-y-3">
                <div className="text-xs font-mono text-ink-400 uppercase tracking-wider">
                  The Deterministic Analysis Pipeline:
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs font-mono">
                  {[
                    { step: "01", name: "Scope Ingestion", desc: "Filters tests & fixtures" },
                    { step: "02", name: "AST Extraction", desc: "Language visitor parse" },
                    { step: "03", name: "Cross-File Topology", desc: "Maps route & import graph" },
                    { step: "04", name: "Penalty Scoring", desc: "Normalized math audit" },
                    { step: "05", name: "AI Remediation", desc: "Explains real AST nodes" },
                  ].map((p) => (
                    <div
                      key={p.step}
                      className="p-3 rounded-lg bg-ink-950/80 border border-border space-y-1"
                    >
                      <div className="text-red-400 font-bold text-[11px]">{p.step}</div>
                      <div className="text-white font-medium text-[11px]">{p.name}</div>
                      <div className="text-ink-500 text-[10px]">{p.desc}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

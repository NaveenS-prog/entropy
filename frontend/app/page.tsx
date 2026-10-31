"use client";

import { useEffect, useState } from "react";
import {
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
  SystemHealth,
} from "@/types";
import { EntropyCommandDeck, WorkspaceId } from "@/components/EntropyCommandDeck";
import { WorkspaceExecutive } from "@/components/workspaces/WorkspaceExecutive";
import { WorkspaceFindings } from "@/components/workspaces/WorkspaceFindings";
import { WorkspaceArchitecture } from "@/components/workspaces/WorkspaceArchitecture";
import { WorkspaceRoutes } from "@/components/workspaces/WorkspaceRoutes";
import { WorkspacePRDelta } from "@/components/workspaces/WorkspacePRDelta";
import { WorkspacePolicies } from "@/components/workspaces/WorkspacePolicies";
import {
  DEMO_SCAN_RESULT,
  DEMO_SCORE_RESULT,
  DEMO_FINDINGS,
  DEMO_MANIFEST,
} from "@/lib/demoData";
import { AlertTriangle, Loader2 } from "lucide-react";

export default function EntropyPrecisionDashboard() {
  const [activeWorkspace, setActiveWorkspace] = useState<WorkspaceId>("executive");
  const [scans, setScans] = useState<RepositoryScanResult[]>([]);
  const [activeScan, setActiveScan] = useState<RepositoryScanResult | null>(null);
  const [manifest, setManifest] = useState<RepositoryManifest | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [score, setScore] = useState<DebtScoreResult | null>(null);
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<DebtCategory | null>(null);

  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // URL state synchronization on initial mount
  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const ws = params.get("workspace") as WorkspaceId;
      if (
        ws &&
        [
          "executive",
          "findings",
          "architecture",
          "routes",
          "pr_delta",
          "policies",
        ].includes(ws)
      ) {
        setActiveWorkspace(ws);
      }
    }
  }, []);

  // Update URL search query on workspace change
  const handleSelectWorkspace = (ws: WorkspaceId) => {
    setActiveWorkspace(ws);
    if (typeof window !== "undefined") {
      const url = new URL(window.location.href);
      url.searchParams.set("workspace", ws);
      if (activeScan?.scan_id) {
        url.searchParams.set("scanId", activeScan.scan_id);
      }
      window.history.pushState({}, "", url.toString());
    }
  };

  const loadFindingsForScan = async (scanId: string) => {
    try {
      const f = await getFindings(scanId);
      setFindings(f);
    } catch (err) {
      console.warn("Could not load findings from API:", err);
      if (scanId === DEMO_SCAN_RESULT.scan_id) {
        setFindings(DEMO_FINDINGS);
      } else {
        setFindings([]);
      }
    }
  };

  const loadScoreForScan = async (scanId: string) => {
    try {
      const s = await getScore(scanId);
      setScore(s);
    } catch (err) {
      console.warn("Could not load score from API:", err);
      if (scanId === DEMO_SCAN_RESULT.scan_id) {
        setScore(DEMO_SCORE_RESULT);
      } else {
        setScore(null);
      }
    }
  };

  const handleSelectScan = async (scanId: string) => {
    setError(null);
    if (scanId === DEMO_SCAN_RESULT.scan_id) {
      setActiveScan(DEMO_SCAN_RESULT);
      setManifest(DEMO_MANIFEST);
      setFindings(DEMO_FINDINGS);
      setScore(DEMO_SCORE_RESULT);
      return;
    }

    try {
      const full = await getScan(scanId);
      setActiveScan(full);
      if (full.manifest) {
        setManifest(full.manifest);
      } else {
        getManifest(full.scan_id).then(setManifest).catch(() => null);
      }
      loadFindingsForScan(full.scan_id);
      loadScoreForScan(full.scan_id);

      if (typeof window !== "undefined") {
        const url = new URL(window.location.href);
        url.searchParams.set("scanId", scanId);
        window.history.pushState({}, "", url.toString());
      }
    } catch (err) {
      console.error("Failed to load selected scan:", err);
      const fallback = scans.find((s) => s.scan_id === scanId);
      if (fallback) {
        setActiveScan(fallback);
      }
    }
  };

  const handleTriggerScan = async (repoPath: string, repoName?: string) => {
    setIsScanning(true);
    setError(null);
    try {
      const result = await triggerScan(repoPath.trim(), repoName?.trim() || undefined);
      setScans((prev) => [result, ...prev.filter((s) => s.scan_id !== result.scan_id)]);
      setActiveScan(result);

      if (result.manifest) {
        setManifest(result.manifest);
      } else {
        const m = await getManifest(result.scan_id).catch(() => null);
        setManifest(m);
      }

      await Promise.all([
        loadFindingsForScan(result.scan_id),
        loadScoreForScan(result.scan_id),
      ]);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to scan repository";
      setError(msg);
      throw err;
    } finally {
      setIsScanning(false);
    }
  };

  // Initial load
  useEffect(() => {
    async function init() {
      try {
        const [healthData, scanList] = await Promise.all([
          fetchHealth().catch(() => null),
          listScans().catch(() => []),
        ]);

        setHealth(healthData);

        if (scanList.length > 0) {
          setScans(scanList);
          const params =
            typeof window !== "undefined"
              ? new URLSearchParams(window.location.search)
              : null;
          const targetScanId = params?.get("scanId");
          const first =
            (targetScanId && scanList.find((s) => s.scan_id === targetScanId)) ||
            scanList[0];

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
          } catch {
            setActiveScan(first);
            if (first.score) setScore(first.score);
            if (first.findings) setFindings(first.findings);
          }
        } else {
          // Fallback to rich preloaded demo dataset so workspaces are immediately interactive
          setScans([DEMO_SCAN_RESULT]);
          setActiveScan(DEMO_SCAN_RESULT);
          setManifest(DEMO_MANIFEST);
          setFindings(DEMO_FINDINGS);
          setScore(DEMO_SCORE_RESULT);
        }
      } catch (err) {
        console.error("Initialization error:", err);
        setScans([DEMO_SCAN_RESULT]);
        setActiveScan(DEMO_SCAN_RESULT);
        setManifest(DEMO_MANIFEST);
        setFindings(DEMO_FINDINGS);
        setScore(DEMO_SCORE_RESULT);
      }
    }
    init();
  }, []);

  return (
    <div className="space-y-6">
      {/* Swiss High-Tech Command Deck Header & Meta Bar */}
      <EntropyCommandDeck
        activeWorkspace={activeWorkspace}
        onSelectWorkspace={handleSelectWorkspace}
        scans={scans}
        activeScan={activeScan}
        onSelectScan={handleSelectScan}
        findings={findings}
        score={score}
        manifest={manifest}
        health={health}
        isScanning={isScanning}
        onTriggerScan={handleTriggerScan}
      />

      {/* Global Error Banner if any */}
      {error && (
        <div className="bg-red-950/40 border border-red-500/40 rounded-xl p-4 text-xs font-mono text-red-300 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button
            type="button"
            onClick={() => setError(null)}
            className="text-ink-400 hover:text-white"
          >
            ✕
          </button>
        </div>
      )}

      {/* Active Operational Workspace View */}
      <div className="transition-opacity duration-200">
        {activeWorkspace === "executive" && (
          <WorkspaceExecutive
            score={score}
            findings={findings}
            repository={activeScan?.repository}
            durationMs={activeScan?.duration_ms}
            onSelectCategory={(cat) => {
              setSelectedCategory(cat);
              handleSelectWorkspace("findings");
            }}
            onNavigateFindings={() => handleSelectWorkspace("findings")}
          />
        )}

        {activeWorkspace === "findings" && (
          <WorkspaceFindings
            scanId={activeScan?.scan_id || ""}
            findings={findings}
            initialCategory={selectedCategory}
          />
        )}

        {activeWorkspace === "architecture" && (
          <WorkspaceArchitecture
            manifest={manifest}
            findings={findings}
          />
        )}

        {activeWorkspace === "routes" && (
          <WorkspaceRoutes
            findings={findings}
            manifest={manifest}
          />
        )}

        {activeWorkspace === "pr_delta" && (
          <WorkspacePRDelta
            activeScan={activeScan}
            previousScan={scans.find((s) => s.scan_id !== activeScan?.scan_id) || null}
            findings={findings}
          />
        )}

        {activeWorkspace === "policies" && (
          <WorkspacePolicies
            score={score}
            findings={findings}
          />
        )}
      </div>
    </div>
  );
}

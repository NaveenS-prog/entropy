"use client";

import { useEffect, useState } from "react";
import { fetchHealth, listScans } from "@/lib/api";
import { DebtCategory, RepositoryScanResult, SystemHealth } from "@/types";
import { ScoreBanner } from "@/components/dashboard/ScoreBanner";
import { CategoryMatrix } from "@/components/dashboard/CategoryMatrix";
import { FindingsViewer } from "@/components/findings/FindingsViewer";
import { ScanTriggerModal } from "@/components/scans/ScanTriggerModal";
import {
  ShieldAlert,
  Server,
  Terminal,
  Activity,
  Code2,
  FileCheck,
  ChevronDown,
} from "lucide-react";

export default function DashboardPage() {
  const [scans, setScans] = useState<RepositoryScanResult[]>([]);
  const [activeScan, setActiveScan] = useState<RepositoryScanResult | null>(null);
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<DebtCategory | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [showAuditTrail, setShowAuditTrail] = useState(false);

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
          setActiveScan(scanList[0]);
        }
      } catch (err) {
        console.error("Initialization error:", err);
      } finally {
        setIsLoading(false);
      }
    }
    init();
  }, []);

  const handleScanCompleted = (newScan: RepositoryScanResult) => {
    setScans((prev) => [newScan, ...prev.filter((s) => s.scan_id !== newScan.scan_id)]);
    setActiveScan(newScan);
  };

  return (
    <div className="space-y-6">
      {/* Top action bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="relative">
            <select
              value={activeScan?.scan_id || ""}
              onChange={(e) => {
                const found = scans.find((s) => s.scan_id === e.target.value);
                if (found) setActiveScan(found);
              }}
              disabled={scans.length === 0}
              className="appearance-none bg-slate-900 border border-slate-700 text-xs font-semibold text-white rounded-lg pl-3 pr-8 py-2 focus:outline-none focus:border-emerald-500 cursor-pointer disabled:opacity-50"
            >
              {scans.length === 0 ? (
                <option value="">No Active Scans</option>
              ) : (
                scans.map((s) => (
                  <option key={s.scan_id} value={s.scan_id}>
                    {s.repository.name} (Score: {s.score?.total_score ?? "N/A"})
                  </option>
                ))
              )}
            </select>
            <ChevronDown className="h-3.5 w-3.5 text-slate-400 absolute right-2.5 top-3 pointer-events-none" />
          </div>

          {health && (
            <div className="hidden md:flex items-center gap-2 text-xs text-slate-400 font-mono bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800">
              <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
              <span>Backend {health.version}</span>
              <span className="text-slate-600">|</span>
              <span>{health.active_analyzers_count} Analyzers Active</span>
            </div>
          )}
        </div>

        <ScanTriggerModal onScanCompleted={handleScanCompleted} />
      </div>

      {isLoading ? (
        <div className="py-24 text-center">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-2 border-emerald-500 border-t-transparent" />
          <p className="mt-3 text-xs text-slate-400 font-mono">Connecting to SilentGuard Backend Engine...</p>
        </div>
      ) : activeScan && activeScan.score ? (
        <>
          {/* Main Score Banner */}
          <ScoreBanner
            score={activeScan.score}
            repository={activeScan.repository}
            durationMs={activeScan.duration_ms}
          />

          {/* 7 MVP Categories Matrix */}
          <CategoryMatrix
            categories={activeScan.score.category_scores}
            selectedCategory={selectedCategory}
            onSelectCategory={setSelectedCategory}
          />

          {/* Explainable Formula Audit Card */}
          <div className="bg-card border border-border rounded-xl p-4">
            <button
              onClick={() => setShowAuditTrail(!showAuditTrail)}
              className="w-full flex items-center justify-between text-xs font-semibold text-slate-300 hover:text-white"
            >
              <div className="flex items-center gap-2">
                <FileCheck className="h-4 w-4 text-emerald-400" />
                <span>Explainable Debt Scoring Formula & Audit Trail</span>
                <span className="text-[10px] text-emerald-400 bg-emerald-950/60 border border-emerald-800/60 px-2 py-0.5 rounded font-mono">
                  100% Grounded
                </span>
              </div>
              <span className="text-slate-500">{showAuditTrail ? "Hide" : "Show"}</span>
            </button>

            {showAuditTrail && (
              <div className="mt-4 pt-3 border-t border-border/80 text-xs font-mono space-y-2">
                <div className="bg-slate-950 p-3 rounded border border-slate-800 text-slate-300">
                  <p className="text-emerald-400 font-semibold mb-1">Mathematical Formula:</p>
                  <p>{activeScan.score.formula_summary}</p>
                </div>

                <div className="bg-slate-950 p-3 rounded border border-slate-800 text-slate-400 space-y-1">
                  <p className="text-slate-200 font-semibold mb-1">Execution Audit Trail:</p>
                  {activeScan.score.audit_trail.map((entry, idx) => (
                    <div key={idx} className="flex gap-2">
                      <span className="text-slate-600 select-none">{idx + 1}.</span>
                      <span>{entry}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Traceable Findings Viewer */}
          <FindingsViewer
            scanId={activeScan.scan_id}
            findings={activeScan.findings}
            selectedCategory={selectedCategory}
          />
        </>
      ) : (
        /* Empty State */
        <div className="border border-dashed border-slate-800 rounded-2xl p-12 text-center bg-card/40 my-8">
          <div className="h-14 w-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center mx-auto mb-4">
            <ShieldAlert className="h-7 w-7" />
          </div>
          <h2 className="text-xl font-bold text-white tracking-tight">No Active Repository Scanned</h2>
          <p className="text-sm text-slate-400 max-w-lg mx-auto mt-2 leading-relaxed">
            SilentGuard identifies <strong>Silent Security Debt</strong> — observable architectural patterns
            that accumulate maintenance and security risks over time.
          </p>

          <div className="flex items-center justify-center gap-4 mt-6">
            <button
              onClick={() => {
                const btn = document.querySelector('button:has(svg.lucide-sparkles)') as HTMLButtonElement;
                if (btn) btn.click();
              }}
              className="bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs px-5 py-2.5 rounded-lg shadow-md transition-colors"
            >
              Run Built-in Sample Scan
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-3xl mx-auto mt-12 text-left">
            <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/50">
              <Code2 className="h-5 w-5 text-emerald-400 mb-2" />
              <h4 className="text-xs font-bold text-white uppercase tracking-wider">Deterministic AST</h4>
              <p className="text-xs text-slate-400 mt-1">
                Static analysis directly parses abstract syntax trees. No fabricated results.
              </p>
            </div>
            <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/50">
              <Activity className="h-5 w-5 text-cyan-400 mb-2" />
              <h4 className="text-xs font-bold text-white uppercase tracking-wider">Explainable Scoring</h4>
              <p className="text-xs text-slate-400 mt-1">
                0-100 Debt Score derived strictly from categorized finding weights and LOC.
              </p>
            </div>
            <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/50">
              <Server className="h-5 w-5 text-purple-400 mb-2" />
              <h4 className="text-xs font-bold text-white uppercase tracking-wider">Clean Boundaries</h4>
              <p className="text-xs text-slate-400 mt-1">
                Ingestion, Parsing, Analysis, Scoring, and API layers are completely decoupled.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

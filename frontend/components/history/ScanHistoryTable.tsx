"use client";

import React, { useState } from "react";
import { PaginatedScanSnapshots, ScanSnapshot } from "@/types";
import { getTierColor } from "@/lib/utils";
import {
  History,
  GitBranch,
  GitCommit,
  Calendar,
  Layers,
  ArrowRight,
  ChevronLeft,
  ChevronRight,
  GitCompare,
  Eye,
  CheckSquare,
  Square,
} from "lucide-react";

interface ScanHistoryTableProps {
  history: PaginatedScanSnapshots | null;
  activeScanId?: string;
  isLoading?: boolean;
  onSelectScan: (scanId: string) => void;
  onCompareScans: (currentScanId: string, previousScanId: string) => void;
  onPageChange: (newPage: number) => void;
}

export function ScanHistoryTable({
  history,
  activeScanId,
  isLoading,
  onSelectScan,
  onCompareScans,
  onPageChange,
}: ScanHistoryTableProps) {
  const [selectedScanIds, setSelectedScanIds] = useState<string[]>([]);

  const toggleSelectScan = (scanId: string) => {
    setSelectedScanIds((prev) => {
      if (prev.includes(scanId)) {
        return prev.filter((id) => id !== scanId);
      }
      if (prev.length >= 2) {
        // Replace oldest selection
        return [prev[1], scanId];
      }
      return [...prev, scanId];
    });
  };

  const handleCompareSelected = () => {
    if (selectedScanIds.length === 2) {
      // Find their snapshots to order by started_at descending (current is newer)
      const scanA = history?.items.find((s) => s.scan_id === selectedScanIds[0]);
      const scanB = history?.items.find((s) => s.scan_id === selectedScanIds[1]);
      if (scanA && scanB) {
        const isANewer = new Date(scanA.started_at).getTime() >= new Date(scanB.started_at).getTime();
        const current = isANewer ? scanA.scan_id : scanB.scan_id;
        const previous = isANewer ? scanB.scan_id : scanA.scan_id;
        onCompareScans(current, previous);
      }
    }
  };

  if (isLoading) {
    return (
      <div className="bg-card border border-border rounded-xl p-8 flex items-center justify-center min-h-[260px]">
        <div className="flex items-center gap-3 text-slate-400 text-sm">
          <div className="w-5 h-5 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
          <span>Loading historical scans...</span>
        </div>
      </div>
    );
  }

  if (!history || history.items.length === 0) {
    return (
      <div className="bg-card border border-border rounded-xl p-8 text-center space-y-3">
        <History className="w-8 h-8 text-slate-500 mx-auto" />
        <h4 className="text-sm font-semibold text-slate-300">No Scan History Found</h4>
        <p className="text-xs text-slate-500 max-w-md mx-auto">
          Scans executed on this repository will appear here with full metadata, scores, and comparison capabilities.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-card border border-border rounded-xl overflow-hidden shadow-sm space-y-4 p-6">
      {/* Table Header & Comparison Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <History className="w-5 h-5 text-emerald-400" />
            <h3 className="text-sm font-semibold text-white">Repository Scan History</h3>
            <span className="text-xs font-mono text-slate-400">
              ({history.total} total recorded)
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Select any two scans to inspect score deltas, new findings, and resolved debt.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {selectedScanIds.length === 2 ? (
            <button
              onClick={handleCompareSelected}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium transition-colors shadow"
            >
              <GitCompare className="w-4 h-4" />
              <span>Compare Selected (2)</span>
            </button>
          ) : (
            <span className="text-[11px] text-slate-500 font-mono">
              {selectedScanIds.length === 1
                ? "Select 1 more scan to compare"
                : "Select 2 scans to compare"}
            </span>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-slate-900/80 border-b border-border text-slate-400 font-mono">
              <th className="py-2.5 px-3 w-10 text-center">Select</th>
              <th className="py-2.5 px-3">Scan ID</th>
              <th className="py-2.5 px-3">Date &amp; Time</th>
              <th className="py-2.5 px-3">Branch / Commit</th>
              <th className="py-2.5 px-3">Score &amp; Tier</th>
              <th className="py-2.5 px-3">Findings</th>
              <th className="py-2.5 px-3">LOC / Files</th>
              <th className="py-2.5 px-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {history.items.map((scan: ScanSnapshot, index: number) => {
              const isSelected = selectedScanIds.includes(scan.scan_id);
              const isActive = activeScanId === scan.scan_id;
              const tierStyle = getTierColor(scan.score_band || "very_low");
              const nextScan = history.items[index + 1]; // Preceding chronological scan

              return (
                <tr
                  key={scan.scan_id}
                  className={`hover:bg-slate-800/40 transition-colors ${
                    isActive ? "bg-emerald-950/20" : ""
                  }`}
                >
                  {/* Select Checkbox */}
                  <td className="py-3 px-3 text-center">
                    <button
                      type="button"
                      onClick={() => toggleSelectScan(scan.scan_id)}
                      className="text-slate-400 hover:text-emerald-400 transition-colors"
                    >
                      {isSelected ? (
                        <CheckSquare className="w-4 h-4 text-emerald-400" />
                      ) : (
                        <Square className="w-4 h-4" />
                      )}
                    </button>
                  </td>

                  {/* Scan ID */}
                  <td className="py-3 px-3 font-mono">
                    <span className="text-white font-medium">
                      {scan.scan_id.slice(0, 8)}
                    </span>
                    {isActive && (
                      <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded bg-emerald-900/60 text-emerald-300 border border-emerald-700/60">
                        active
                      </span>
                    )}
                  </td>

                  {/* Date & Time */}
                  <td className="py-3 px-3 text-slate-300">
                    <div className="flex items-center gap-1.5">
                      <Calendar className="w-3.5 h-3.5 text-slate-500" />
                      <span>{new Date(scan.started_at).toLocaleString()}</span>
                    </div>
                  </td>

                  {/* Branch / Commit */}
                  <td className="py-3 px-3 text-slate-400 font-mono">
                    <div className="flex flex-col gap-0.5">
                      {scan.branch && (
                        <span className="flex items-center gap-1 text-slate-300">
                          <GitBranch className="w-3 h-3 text-slate-500" />
                          {scan.branch}
                        </span>
                      )}
                      {scan.commit_sha && (
                        <span className="flex items-center gap-1 text-[11px] text-slate-500">
                          <GitCommit className="w-3 h-3" />
                          {scan.commit_sha.slice(0, 7)}
                        </span>
                      )}
                    </div>
                  </td>

                  {/* Score & Tier */}
                  <td className="py-3 px-3">
                    {scan.entropy_score !== null && scan.entropy_score !== undefined ? (
                      <div className="flex items-center gap-2">
                        <span className={`font-mono font-bold text-sm ${tierStyle.text}`}>
                          {scan.entropy_score}
                        </span>
                        <span
                          className={`text-[10px] px-1.5 py-0.5 rounded border font-semibold ${tierStyle.bg} ${tierStyle.text} ${tierStyle.border}`}
                        >
                          {(scan.score_band || "low").replace("_", " ").toUpperCase()}
                        </span>
                      </div>
                    ) : (
                      <span className="text-slate-500 italic">Not scored</span>
                    )}
                  </td>

                  {/* Findings */}
                  <td className="py-3 px-3 font-mono">
                    <span
                      className={`font-semibold ${
                        scan.finding_count > 0 ? "text-amber-400" : "text-emerald-400"
                      }`}
                    >
                      {scan.finding_count}
                    </span>
                  </td>

                  {/* LOC / Files */}
                  <td className="py-3 px-3 text-slate-400 font-mono text-[11px]">
                    <div>{scan.total_loc.toLocaleString()} LOC</div>
                    <div className="text-slate-500">{scan.analyzed_files} files</div>
                  </td>

                  {/* Actions */}
                  <td className="py-3 px-3 text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      <button
                        onClick={() => onSelectScan(scan.scan_id)}
                        title="View details for this scan"
                        className="p-1.5 rounded hover:bg-slate-700/60 text-slate-300 hover:text-white transition-colors"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>

                      {nextScan && (
                        <button
                          onClick={() => onCompareScans(scan.scan_id, nextScan.scan_id)}
                          title="Compare with immediate predecessor"
                          className="flex items-center gap-1 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-[11px] font-medium transition-colors"
                        >
                          <GitCompare className="w-3 h-3" />
                          <span>vs prev</span>
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination Controls */}
      {history.total_pages > 1 && (
        <div className="flex items-center justify-between pt-2 text-xs text-slate-400">
          <div>
            Page {history.page} of {history.total_pages}
          </div>
          <div className="flex items-center gap-2">
            <button
              disabled={history.page <= 1}
              onClick={() => onPageChange(history.page - 1)}
              className="p-1.5 rounded bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-700 text-slate-300 transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              disabled={history.page >= history.total_pages}
              onClick={() => onPageChange(history.page + 1)}
              className="p-1.5 rounded bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-700 text-slate-300 transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

"use client";

import React, { useState } from "react";
import { PaginatedScanSnapshots, ScanSnapshot } from "@/types";
import { getTierColor } from "@/lib/utils";
import {
  History,
  GitBranch,
  GitCommit,
  Calendar,
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
        return [prev[1], scanId];
      }
      return [...prev, scanId];
    });
  };

  const handleCompareSelected = () => {
    if (selectedScanIds.length === 2) {
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
      <div className="bg-card border border-border rounded-xl p-8 flex items-center justify-center min-h-[220px]">
        <div className="flex items-center gap-2.5 text-ink-400 text-xs font-mono">
          <div className="w-4 h-4 border-2 border-ink-400 border-t-transparent rounded-full animate-spin" />
          <span>Loading historical scans...</span>
        </div>
      </div>
    );
  }

  if (!history || history.items.length === 0) {
    return (
      <div className="bg-card border border-border rounded-xl p-8 text-center space-y-2">
        <History className="w-6 h-6 text-ink-500 mx-auto" />
        <h4 className="text-xs font-medium text-white">No scan history found</h4>
        <p className="text-xs text-ink-400 max-w-sm mx-auto">
          Executed scans on this repository will appear here with scores and comparison options
        </p>
      </div>
    );
  }

  return (
    <div className="bg-card border border-border rounded-xl p-5 space-y-4">
      {/* Header & Comparison Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <History className="w-4 h-4 text-ink-400" />
            <h3 className="text-xs font-medium text-ink-200 uppercase tracking-wider">Scan history</h3>
            <span className="text-xs font-mono text-ink-500 tabular-nums">
              ({history.total} recorded)
            </span>
          </div>
          <p className="text-xs text-ink-400 mt-0.5">
            Select any two scans to inspect score deltas and resolved debt
          </p>
        </div>

        <div className="flex items-center gap-2">
          {selectedScanIds.length === 2 ? (
            <button
              onClick={handleCompareSelected}
              className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-ink-800 hover:bg-ink-700 text-white text-xs font-medium transition-colors border border-border"
            >
              <GitCompare className="w-3.5 h-3.5" />
              <span>Compare selected (2)</span>
            </button>
          ) : (
            <span className="text-[11px] text-ink-500 font-mono">
              {selectedScanIds.length === 1
                ? "Select 1 more scan"
                : "Select 2 scans to compare"}
            </span>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-ink-850 border-b border-border text-ink-400 font-mono text-[11px]">
              <th className="py-2.5 px-3 w-10 text-center font-normal">Select</th>
              <th className="py-2.5 px-3 font-normal">Scan ID</th>
              <th className="py-2.5 px-3 font-normal">Date &amp; time</th>
              <th className="py-2.5 px-3 font-normal">Branch / commit</th>
              <th className="py-2.5 px-3 font-normal">Score &amp; tier</th>
              <th className="py-2.5 px-3 font-normal">Findings</th>
              <th className="py-2.5 px-3 font-normal">LOC / files</th>
              <th className="py-2.5 px-3 text-right font-normal">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {history.items.map((scan: ScanSnapshot, index: number) => {
              const isSelected = selectedScanIds.includes(scan.scan_id);
              const isActive = activeScanId === scan.scan_id;
              const tierStyle = getTierColor(scan.score_band || "very_low");
              const nextScan = history.items[index + 1];

              return (
                <tr
                  key={scan.scan_id}
                  className={`hover:bg-ink-850/50 transition-colors ${
                    isActive ? "bg-ink-800/40" : ""
                  }`}
                >
                  {/* Select Checkbox */}
                  <td className="py-2.5 px-3 text-center">
                    <button
                      type="button"
                      onClick={() => toggleSelectScan(scan.scan_id)}
                      className="text-ink-400 hover:text-white transition-colors"
                    >
                      {isSelected ? (
                        <CheckSquare className="w-4 h-4 text-emerald-400" />
                      ) : (
                        <Square className="w-4 h-4" />
                      )}
                    </button>
                  </td>

                  {/* Scan ID */}
                  <td className="py-2.5 px-3 font-mono">
                    <span className="text-ink-100 font-medium">
                      {scan.scan_id.slice(0, 8)}
                    </span>
                    {isActive && (
                      <span className="ml-2 text-[10px] px-1.5 py-0.2 rounded bg-ink-800 text-emerald-400 border border-border">
                        active
                      </span>
                    )}
                  </td>

                  {/* Date & Time */}
                  <td className="py-2.5 px-3 text-ink-300 font-mono text-[11px]">
                    <div className="flex items-center gap-1.5">
                      <Calendar className="w-3 h-3 text-ink-500" />
                      <span>{new Date(scan.started_at).toLocaleDateString()} {new Date(scan.started_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                    </div>
                  </td>

                  {/* Branch / Commit */}
                  <td className="py-2.5 px-3 text-ink-400 font-mono text-[11px]">
                    <div className="flex flex-col gap-0.5">
                      {scan.branch && (
                        <span className="flex items-center gap-1 text-ink-300">
                          <GitBranch className="w-3 h-3 text-ink-500" />
                          {scan.branch}
                        </span>
                      )}
                      {scan.commit_sha && (
                        <span className="flex items-center gap-1 text-ink-500">
                          <GitCommit className="w-3 h-3" />
                          {scan.commit_sha.slice(0, 7)}
                        </span>
                      )}
                    </div>
                  </td>

                  {/* Score & Tier */}
                  <td className="py-2.5 px-3">
                    {scan.entropy_score !== null && scan.entropy_score !== undefined ? (
                      <div className="flex items-center gap-2">
                        <span className={`font-mono font-medium text-xs tabular-nums ${tierStyle.text}`}>
                          {scan.entropy_score}
                        </span>
                        <span
                          className={`text-[10px] px-1.5 py-0.2 rounded border font-mono ${tierStyle.bg} ${tierStyle.text} ${tierStyle.border}`}
                        >
                          {(scan.score_band || "low").replace("_", " ")}
                        </span>
                      </div>
                    ) : (
                      <span className="text-ink-500 italic text-xs">Not scored</span>
                    )}
                  </td>

                  {/* Findings */}
                  <td className="py-2.5 px-3 font-mono tabular-nums text-xs">
                    <span
                      className={
                        scan.finding_count > 0 ? "text-amber-300" : "text-emerald-400"
                      }
                    >
                      {scan.finding_count}
                    </span>
                  </td>

                  {/* LOC / Files */}
                  <td className="py-2.5 px-3 text-ink-400 font-mono text-[11px] tabular-nums">
                    <div>{scan.total_loc.toLocaleString()} LOC</div>
                    <div className="text-ink-500">{scan.analyzed_files} files</div>
                  </td>

                  {/* Actions */}
                  <td className="py-2.5 px-3 text-right">
                    <div className="flex items-center justify-end gap-1">
                      <button
                        onClick={() => onSelectScan(scan.scan_id)}
                        title="View details for this scan"
                        className="p-1 rounded hover:bg-ink-800 text-ink-400 hover:text-white transition-colors"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>

                      {nextScan && (
                        <button
                          onClick={() => onCompareScans(scan.scan_id, nextScan.scan_id)}
                          title="Compare with immediate predecessor"
                          className="flex items-center gap-1 px-2 py-0.5 rounded bg-ink-800 hover:bg-ink-700 text-ink-300 hover:text-white text-[11px] font-mono transition-colors border border-border"
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
        <div className="flex items-center justify-between pt-2 text-xs text-ink-400 font-mono">
          <div>
            Page {history.page} of {history.total_pages}
          </div>
          <div className="flex items-center gap-1.5">
            <button
              disabled={history.page <= 1}
              onClick={() => onPageChange(history.page - 1)}
              className="p-1.5 rounded bg-ink-850 disabled:opacity-30 disabled:cursor-not-allowed hover:bg-ink-800 text-ink-300 border border-border transition-colors"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
            </button>
            <button
              disabled={history.page >= history.total_pages}
              onClick={() => onPageChange(history.page + 1)}
              className="p-1.5 rounded bg-ink-850 disabled:opacity-30 disabled:cursor-not-allowed hover:bg-ink-800 text-ink-300 border border-border transition-colors"
            >
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

"use client";

import React, { useState } from "react";
import { RepositoryTrendResponse, TrendPoint } from "@/types";
import { getTierColor } from "@/lib/utils";
import { TrendingUp, Calendar, GitCommit, GitBranch, AlertCircle, Info } from "lucide-react";

interface ScoreTrendChartProps {
  trend: RepositoryTrendResponse | null;
  isLoading?: boolean;
  onSelectScan?: (scanId: string) => void;
}

export function ScoreTrendChart({ trend, isLoading, onSelectScan }: ScoreTrendChartProps) {
  const [hoveredPoint, setHoveredPoint] = useState<TrendPoint | null>(null);

  if (isLoading) {
    return (
      <div className="bg-card border border-border rounded-xl p-6 flex items-center justify-center min-h-[220px]">
        <div className="flex items-center gap-3 text-slate-400 text-sm">
          <div className="w-5 h-5 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
          <span>Loading historical score trend...</span>
        </div>
      </div>
    );
  }

  if (!trend || trend.total_scans === 0 || trend.points.length === 0) {
    return (
      <div className="bg-card border border-border rounded-xl p-6 flex flex-col items-center justify-center min-h-[200px] text-center space-y-3">
        <div className="w-10 h-10 rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center text-slate-400">
          <Info className="w-5 h-5" />
        </div>
        <p className="text-sm font-medium text-slate-300">
          {trend?.message || "No scan history available"}
        </p>
        <p className="text-xs text-slate-500 max-w-sm">
          Execute additional scans on this repository to observe debt trajectory over time.
        </p>
      </div>
    );
  }

  if (trend.total_scans === 1 || trend.points.length === 1) {
    const single = trend.points[0];
    const tierStyle = getTierColor(single.tier);

    return (
      <div className="bg-card border border-border rounded-xl p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-emerald-400" />
            <h3 className="text-sm font-semibold text-white">Debt Score Trajectory</h3>
          </div>
          <span className="text-xs text-slate-400 font-mono">1 recorded scan</span>
        </div>

        <div className="p-4 rounded-lg bg-slate-900/50 border border-slate-800 flex items-center justify-between">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className={`text-2xl font-bold font-mono ${tierStyle.text}`}>
                {single.entropy_score} / 100
              </span>
              <span className={`text-xs px-2 py-0.5 rounded font-semibold border ${tierStyle.bg} ${tierStyle.text} ${tierStyle.border}`}>
                {single.tier.replace("_", " ").toUpperCase()}
              </span>
            </div>
            <div className="flex items-center gap-3 text-xs text-slate-400 font-mono">
              <span className="flex items-center gap-1">
                <Calendar className="w-3.5 h-3.5" />
                {new Date(single.timestamp).toLocaleString()}
              </span>
              {single.commit_hash && (
                <span className="flex items-center gap-1">
                  <GitCommit className="w-3.5 h-3.5" />
                  {single.commit_hash.slice(0, 7)}
                </span>
              )}
            </div>
          </div>
          <div className="text-right">
            <p className="text-xs text-slate-400 italic">
              {trend.message || "Not enough historical data for a trend"}
            </p>
            <p className="text-[11px] text-slate-500 mt-1">
              Minimum 2 scans required for directional deltas
            </p>
          </div>
        </div>
      </div>
    );
  }

  // Multi-point trend chart (chronological: points[0] is oldest, points[last] is newest)
  const points = trend.points;
  const width = 640;
  const height = 180;
  const padX = 40;
  const padY = 30;
  const chartW = width - padX * 2;
  const chartH = height - padY * 2;

  // Max score scale is always 100 (Entropy debt score domain 0-100)
  const maxScore = 100;
  const minScore = 0;

  const getX = (idx: number) => padX + (idx / (points.length - 1)) * chartW;
  const getY = (val: number) => padY + chartH - (val / (maxScore - minScore)) * chartH;

  const svgPoints = points.map((p, i) => `${getX(i)},${getY(p.entropy_score)}`).join(" ");

  const firstScore = points[0].entropy_score;
  const latestScore = points[points.length - 1].entropy_score;
  const netDelta = latestScore - firstScore;

  return (
    <div className="bg-card border border-border rounded-xl p-6 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-emerald-400" />
            <h3 className="text-sm font-semibold text-white">Debt Score Trajectory</h3>
            <span className="text-xs text-slate-400 font-mono">
              ({points.length} scans)
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Chronological progression of total Entropy Debt Score across recorded scans.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-right">
            <span className="text-xs text-slate-400 block">Net Progression</span>
            <span
              className={`text-xs font-mono font-semibold ${
                netDelta > 0
                  ? "text-rose-400"
                  : netDelta < 0
                  ? "text-emerald-400"
                  : "text-slate-300"
              }`}
            >
              {netDelta > 0 ? `+${netDelta} pts` : netDelta < 0 ? `${netDelta} pts` : "0 (neutral)"}
            </span>
          </div>
        </div>
      </div>

      {/* SVG Line Chart */}
      <div className="relative bg-slate-950/60 rounded-lg border border-slate-800/80 p-3 overflow-hidden">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="w-full h-44 overflow-visible"
        >
          {/* Horizontal grid lines */}
          {[0, 25, 50, 75, 100].map((level) => {
            const y = getY(level);
            return (
              <g key={level}>
                <line
                  x1={padX}
                  y1={y}
                  x2={width - padX}
                  y2={y}
                  stroke="#334155"
                  strokeDasharray="3 3"
                  strokeWidth="0.8"
                />
                <text
                  x={padX - 8}
                  y={y + 3}
                  textAnchor="end"
                  fontSize="10"
                  fill="#64748b"
                  fontFamily="monospace"
                >
                  {level}
                </text>
              </g>
            );
          })}

          {/* Area fill */}
          <polygon
            points={`${padX},${getY(0)} ${svgPoints} ${getX(points.length - 1)},${getY(0)}`}
            fill="rgba(16, 185, 129, 0.08)"
          />

          {/* Line stroke */}
          <polyline
            fill="none"
            stroke="#10b981"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            points={svgPoints}
          />

          {/* Data Points */}
          {points.map((pt, idx) => {
            const cx = getX(idx);
            const cy = getY(pt.entropy_score);
            const isHovered = hoveredPoint?.scan_id === pt.scan_id;

            return (
              <g
                key={pt.scan_id}
                className="cursor-pointer transition-all duration-150"
                onMouseEnter={() => setHoveredPoint(pt)}
                onMouseLeave={() => setHoveredPoint(null)}
                onClick={() => onSelectScan?.(pt.scan_id)}
              >
                <circle
                  cx={cx}
                  cy={cy}
                  r={isHovered ? 6 : 4}
                  fill={isHovered ? "#34d399" : "#10b981"}
                  stroke="#0f172a"
                  strokeWidth="2"
                />
              </g>
            );
          })}
        </svg>

        {/* Hover / Tooltip Card */}
        {hoveredPoint && (
          <div className="absolute top-2 right-2 bg-slate-900 border border-slate-700 rounded-lg p-3 text-xs space-y-1.5 shadow-xl max-w-xs z-20">
            <div className="flex items-center justify-between gap-3">
              <span className="font-semibold text-white">Scan Point</span>
              <span className="font-mono text-emerald-400 font-bold">
                {hoveredPoint.entropy_score} / 100
              </span>
            </div>
            <div className="text-slate-400 font-mono text-[11px] space-y-0.5">
              <div>Date: {new Date(hoveredPoint.timestamp).toLocaleString()}</div>
              {hoveredPoint.commit_hash && (
                <div>Commit: {hoveredPoint.commit_hash.slice(0, 8)}</div>
              )}
              {hoveredPoint.branch && <div>Branch: {hoveredPoint.branch}</div>}
              <div>Findings: {hoveredPoint.total_findings}</div>
            </div>
            <div className="pt-1 border-t border-slate-800 text-[10px] text-slate-500 italic">
              Click to view this scan
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

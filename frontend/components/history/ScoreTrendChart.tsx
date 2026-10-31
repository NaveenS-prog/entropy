"use client";

import React, { useState } from "react";
import { RepositoryTrendResponse, TrendPoint } from "@/types";
import { getTierColor } from "@/lib/utils";
import { TrendingUp, Calendar, GitCommit, Info } from "lucide-react";

interface ScoreTrendChartProps {
  trend: RepositoryTrendResponse | null;
  isLoading?: boolean;
  onSelectScan?: (scanId: string) => void;
}

export function ScoreTrendChart({ trend, isLoading, onSelectScan }: ScoreTrendChartProps) {
  const [hoveredPoint, setHoveredPoint] = useState<TrendPoint | null>(null);

  if (isLoading) {
    return (
      <div className="bg-card border border-border rounded-xl p-6 flex items-center justify-center min-h-[200px]">
        <div className="flex items-center gap-2.5 text-ink-400 text-xs font-mono">
          <div className="w-4 h-4 border-2 border-ink-400 border-t-transparent rounded-full animate-spin" />
          <span>Loading score trend...</span>
        </div>
      </div>
    );
  }

  if (!trend || trend.total_scans === 0 || trend.points.length === 0) {
    return (
      <div className="bg-card border border-border rounded-xl p-6 flex flex-col items-center justify-center min-h-[180px] text-center space-y-2">
        <div className="w-8 h-8 rounded-md bg-ink-800 border border-border flex items-center justify-center text-ink-500">
          <Info className="w-4 h-4" />
        </div>
        <p className="text-xs font-medium text-white">
          {trend?.message || "No scan history available"}
        </p>
        <p className="text-xs text-ink-500 max-w-sm">
          Execute additional scans on this repository to observe trajectory over time
        </p>
      </div>
    );
  }

  if (trend.total_scans === 1 || trend.points.length === 1) {
    const single = trend.points[0];
    const tierStyle = getTierColor(single.tier);

    return (
      <div className="bg-card border border-border rounded-xl p-5 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-ink-400" />
            <h3 className="text-xs font-medium text-ink-200 uppercase tracking-wider">Score trajectory</h3>
          </div>
          <span className="text-xs text-ink-500 font-mono">1 recorded scan</span>
        </div>

        <div className="p-3.5 rounded-lg bg-ink-850 border border-border flex items-center justify-between">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className={`text-xl font-medium font-mono tabular-nums ${tierStyle.text}`}>
                {single.entropy_score} / 100
              </span>
              <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono border ${tierStyle.bg} ${tierStyle.text} ${tierStyle.border}`}>
                {single.tier.replace("_", " ")}
              </span>
            </div>
            <div className="flex items-center gap-3 text-xs text-ink-400 font-mono">
              <span className="flex items-center gap-1">
                <Calendar className="w-3 h-3 text-ink-500" />
                {new Date(single.timestamp).toLocaleString()}
              </span>
              {single.commit_hash && (
                <span className="flex items-center gap-1">
                  <GitCommit className="w-3 h-3 text-ink-500" />
                  {single.commit_hash.slice(0, 7)}
                </span>
              )}
            </div>
          </div>
          <div className="text-right">
            <p className="text-xs text-ink-400">
              {trend.message || "Single baseline scan"}
            </p>
            <p className="text-[11px] text-ink-500 mt-0.5">
              Minimum 2 scans required for directional deltas
            </p>
          </div>
        </div>
      </div>
    );
  }

  const points = trend.points;
  const width = 640;
  const height = 180;
  const padX = 40;
  const padY = 30;
  const chartW = width - padX * 2;
  const chartH = height - padY * 2;

  const maxScore = 100;
  const minScore = 0;

  const getX = (idx: number) => padX + (idx / (points.length - 1)) * chartW;
  const getY = (val: number) => padY + chartH - (val / (maxScore - minScore)) * chartH;

  const svgPoints = points.map((p, i) => `${getX(i)},${getY(p.entropy_score)}`).join(" ");

  const firstScore = points[0].entropy_score;
  const latestScore = points[points.length - 1].entropy_score;
  const netDelta = latestScore - firstScore;

  return (
    <div className="bg-card border border-border rounded-xl p-5 space-y-3">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-ink-400" />
            <h3 className="text-xs font-medium text-ink-200 uppercase tracking-wider">Score trajectory</h3>
            <span className="text-xs text-ink-500 font-mono">
              ({points.length} scans)
            </span>
          </div>
          <p className="text-xs text-ink-400 mt-0.5">
            Chronological progression of total debt score across recorded scans
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-right">
            <span className="text-xs text-ink-500 block">Net delta</span>
            <span
              className={`text-xs font-mono font-medium tabular-nums ${
                netDelta > 0
                  ? "text-red-400"
                  : netDelta < 0
                  ? "text-emerald-400"
                  : "text-ink-300"
              }`}
            >
              {netDelta > 0 ? `+${netDelta} pts` : netDelta < 0 ? `${netDelta} pts` : "0 (neutral)"}
            </span>
          </div>
        </div>
      </div>

      {/* SVG Line Chart */}
      <div className="relative bg-ink-950 rounded-lg border border-border p-3 overflow-hidden">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="w-full h-40 overflow-visible"
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
                  stroke="#20242e"
                  strokeDasharray="3 3"
                  strokeWidth="0.8"
                />
                <text
                  x={padX - 8}
                  y={y + 3}
                  textAnchor="end"
                  fontSize="10"
                  fill="#707b91"
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
            fill="rgba(52, 211, 153, 0.05)"
          />

          {/* Line stroke */}
          <polyline
            fill="none"
            stroke="#34d399"
            strokeWidth="1.5"
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
                className="cursor-pointer"
                onMouseEnter={() => setHoveredPoint(pt)}
                onMouseLeave={() => setHoveredPoint(null)}
                onClick={() => onSelectScan?.(pt.scan_id)}
              >
                <circle
                  cx={cx}
                  cy={cy}
                  r={isHovered ? 5 : 3.5}
                  fill={isHovered ? "#34d399" : "#13161b"}
                  stroke="#34d399"
                  strokeWidth="1.5"
                />
              </g>
            );
          })}
        </svg>

        {/* Hover / Tooltip Card */}
        {hoveredPoint && (
          <div className="absolute top-2 right-2 bg-ink-850 border border-border rounded-lg p-3 text-xs space-y-1 shadow-md max-w-xs z-20">
            <div className="flex items-center justify-between gap-3">
              <span className="font-medium text-white">Scan point</span>
              <span className="font-mono text-emerald-400 font-medium tabular-nums">
                {hoveredPoint.entropy_score} / 100
              </span>
            </div>
            <div className="text-ink-400 font-mono text-[11px] space-y-0.5">
              <div>Date: {new Date(hoveredPoint.timestamp).toLocaleString()}</div>
              {hoveredPoint.commit_hash && (
                <div>Commit: {hoveredPoint.commit_hash.slice(0, 8)}</div>
              )}
              {hoveredPoint.branch && <div>Branch: {hoveredPoint.branch}</div>}
              <div>Findings: {hoveredPoint.total_findings}</div>
            </div>
            <div className="pt-1 border-t border-border text-[10px] text-ink-500 italic">
              Click to view this scan
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

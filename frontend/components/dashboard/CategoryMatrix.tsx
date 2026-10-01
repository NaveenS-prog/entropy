"use client";

import { CategoryScoreBreakdown, DebtCategory } from "@/types";
import {
  AlertTriangle,
  KeyRound,
  ShieldCheck,
  CheckSquare,
  FileText,
  Copy,
  Layers,
} from "lucide-react";

interface CategoryMatrixProps {
  categories: Record<DebtCategory, CategoryScoreBreakdown>;
  selectedCategory?: DebtCategory | null;
  onSelectCategory?: (category: DebtCategory | null) => void;
}

const CATEGORY_META: Record<
  DebtCategory,
  { title: string; icon: React.ComponentType<{ className?: string }> }
> = {
  error_handling: { title: "Error Handling", icon: AlertTriangle },
  authentication_consistency: { title: "Authentication Consistency", icon: KeyRound },
  authorization_consistency: { title: "Authorization Consistency", icon: ShieldCheck },
  input_validation: { title: "Input Validation", icon: CheckSquare },
  logging_and_secrets: { title: "Logging & Secrets", icon: FileText },
  code_duplication: { title: "Duplication & Boilerplate", icon: Copy },
  architectural_consistency: { title: "Architectural Consistency", icon: Layers },
};

export function CategoryMatrix({
  categories,
  selectedCategory,
  onSelectCategory,
}: CategoryMatrixProps) {
  return (
    <div className="mt-8">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-lg font-bold text-white tracking-tight">
            MVP Analysis Categories Breakdown
          </h2>
          <p className="text-xs text-slate-400">
            Modular architectural domains contributing to the total Silent Security Debt Score
          </p>
        </div>
        {selectedCategory && (
          <button
            onClick={() => onSelectCategory && onSelectCategory(null)}
            className="text-xs text-emerald-400 hover:underline"
          >
            Clear category filter
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {Object.entries(categories).map(([key, breakdown]) => {
          const categoryKey = key as DebtCategory;
          const meta = CATEGORY_META[categoryKey];
          const Icon = meta.icon;
          const isSelected = selectedCategory === categoryKey;

          // Color scale for category score
          let scoreColor = "text-emerald-400";
          let barBg = "bg-emerald-500";
          if (breakdown.score > 60) {
            scoreColor = "text-red-400";
            barBg = "bg-red-500";
          } else if (breakdown.score > 30) {
            scoreColor = "text-amber-400";
            barBg = "bg-amber-500";
          } else if (breakdown.score > 0) {
            scoreColor = "text-cyan-400";
            barBg = "bg-cyan-500";
          }

          return (
            <div
              key={categoryKey}
              onClick={() => onSelectCategory && onSelectCategory(isSelected ? null : categoryKey)}
              className={`p-4 rounded-xl border transition-all cursor-pointer bg-card hover:bg-card-hover ${
                isSelected
                  ? "border-emerald-500 ring-1 ring-emerald-500/50 shadow-lg"
                  : "border-border hover:border-slate-700"
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="h-8 w-8 rounded-lg bg-slate-800/80 border border-slate-700/60 flex items-center justify-center text-slate-300">
                  <Icon className="h-4 w-4" />
                </div>
                <div className="text-right">
                  <span className={`text-xl font-bold font-mono ${scoreColor}`}>
                    {breakdown.score}
                  </span>
                  <span className="text-[10px] text-slate-500 ml-0.5">/100</span>
                </div>
              </div>

              <div className="mt-3">
                <h3 className="text-sm font-semibold text-white tracking-tight">{meta.title}</h3>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Weight: {(breakdown.weight * 100).toFixed(0)}% • Findings: {breakdown.finding_count}
                </p>
              </div>

              {/* Progress mini bar */}
              <div className="w-full h-1.5 bg-slate-800 rounded-full mt-3 overflow-hidden">
                <div
                  className={`h-full ${barBg} transition-all duration-500`}
                  style={{ width: `${Math.max(breakdown.score > 0 ? 5 : 0, breakdown.score)}%` }}
                />
              </div>

              {/* Severity mini badges */}
              <div className="flex items-center gap-1.5 mt-3 text-[10px] text-slate-400">
                {breakdown.severity_counts.critical > 0 && (
                  <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 font-mono">
                    {breakdown.severity_counts.critical} crit
                  </span>
                )}
                {breakdown.severity_counts.high > 0 && (
                  <span className="px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-300 font-mono">
                    {breakdown.severity_counts.high} high
                  </span>
                )}
                {breakdown.severity_counts.medium > 0 && (
                  <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 font-mono">
                    {breakdown.severity_counts.medium} med
                  </span>
                )}
                {breakdown.finding_count === 0 && (
                  <span className="text-slate-500 italic">No debt detected</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

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
  Clock,
  CheckCircle2,
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
  error_handling: { title: "Error Handling Debt", icon: AlertTriangle },
  authentication_consistency: { title: "Authentication Consistency", icon: KeyRound },
  authorization_consistency: { title: "Authorization Consistency", icon: ShieldCheck },
  input_validation: { title: "Input Validation Debt", icon: CheckSquare },
  logging_and_secrets: { title: "Logging & Secret-Handling", icon: FileText },
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
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
        <div>
          <h2 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
            <span>Architectural Debt Categories Breakdown</span>
            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
              Analyzed vs Scheduled
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Only categories with implemented analyzers contribute to the Entropy Score. Unanalyzed categories never receive fabricated scores.
          </p>
        </div>
        {selectedCategory && (
          <button
            onClick={() => onSelectCategory && onSelectCategory(null)}
            className="text-xs text-emerald-400 hover:underline font-mono"
          >
            Clear category filter
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        {Object.entries(categories).map(([key, breakdown]) => {
          const categoryKey = key as DebtCategory;
          const meta = CATEGORY_META[categoryKey];
          const Icon = meta ? meta.icon : Layers;
          const isSelected = selectedCategory === categoryKey;
          const isAnalyzed = breakdown.status === "analyzed";

          // Color scale for category score
          let scoreColor = "text-slate-500";
          let barBg = "bg-slate-700";
          if (isAnalyzed && breakdown.score !== null) {
            if (breakdown.score > 60) {
              scoreColor = "text-red-400";
              barBg = "bg-red-500";
            } else if (breakdown.score > 30) {
              scoreColor = "text-amber-400";
              barBg = "bg-amber-500";
            } else if (breakdown.score > 0) {
              scoreColor = "text-cyan-400";
              barBg = "bg-cyan-500";
            } else {
              scoreColor = "text-emerald-400";
              barBg = "bg-emerald-500";
            }
          }

          return (
            <div
              key={categoryKey}
              onClick={() => {
                if (isAnalyzed && onSelectCategory) {
                  onSelectCategory(isSelected ? null : categoryKey);
                }
              }}
              className={`p-4 rounded-xl border transition-all bg-card ${
                isAnalyzed ? "cursor-pointer hover:border-slate-700" : "opacity-75 cursor-default"
              } ${
                isSelected
                  ? "border-emerald-500 ring-1 ring-emerald-500/50 shadow-lg"
                  : "border-border"
              }`}
            >
              {/* Header with status badge */}
              <div className="flex items-center justify-between">
                <div className="h-8 w-8 rounded-lg bg-slate-800/80 border border-slate-700/60 flex items-center justify-center text-slate-300">
                  <Icon className="h-4 w-4" />
                </div>

                <div className="text-right">
                  {isAnalyzed && breakdown.score !== null ? (
                    <div>
                      <span className={`text-lg font-bold font-mono ${scoreColor}`}>
                        {breakdown.score}
                      </span>
                      <span className="text-[10px] text-slate-500 ml-0.5">/100</span>
                    </div>
                  ) : (
                    <span className="text-xs font-mono text-slate-500 font-semibold">—</span>
                  )}
                </div>
              </div>

              <div className="mt-3">
                <div className="flex items-center justify-between gap-1.5">
                  <h3 className="text-xs font-semibold text-white tracking-tight truncate">
                    {meta ? meta.title : categoryKey}
                  </h3>
                </div>

                <div className="flex items-center gap-1.5 mt-1.5">
                  {isAnalyzed ? (
                    <span className="text-[10px] text-emerald-400 bg-emerald-950/60 border border-emerald-900 px-1.5 py-0.5 rounded font-mono flex items-center gap-1">
                      <CheckCircle2 className="h-2.5 w-2.5" />
                      <span>ANALYZED ({breakdown.finding_count} findings)</span>
                    </span>
                  ) : (
                    <span className="text-[10px] text-slate-400 bg-slate-900 border border-slate-800 px-1.5 py-0.5 rounded font-mono flex items-center gap-1">
                      <Clock className="h-2.5 w-2.5 text-slate-500" />
                      <span>NOT ANALYZED YET</span>
                    </span>
                  )}
                </div>
              </div>

              {/* Progress mini bar */}
              <div className="w-full h-1.5 bg-slate-800 rounded-full mt-3 overflow-hidden">
                <div
                  className={`h-full ${barBg} transition-all duration-500`}
                  style={{
                    width: isAnalyzed && breakdown.score !== null ? `${Math.max(breakdown.score > 0 ? 5 : 0, breakdown.score)}%` : "0%",
                  }}
                />
              </div>

              {/* Description & Status text */}
              <div className="mt-2.5 text-[10px] text-slate-400 leading-tight">
                {isAnalyzed ? (
                  <span>
                    Base Weight: {(breakdown.weight * 100).toFixed(0)}% • Contributes to overall score
                  </span>
                ) : (
                  <span className="text-slate-500 italic">
                    Scheduled for future phase. Zero score fabricated.
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

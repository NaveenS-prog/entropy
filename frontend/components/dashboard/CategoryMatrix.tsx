"use client";

import { CategoryScoreBreakdown, DebtCategory, ScoringCoverage } from "@/types";
import {
  AlertTriangle,
  KeyRound,
  ShieldCheck,
  CheckSquare,
  FileText,
  Copy,
  Layers,
  Clock,
  Globe,
  Radio,
} from "lucide-react";

interface CategoryMatrixProps {
  categories: Record<DebtCategory, CategoryScoreBreakdown>;
  coverage?: ScoringCoverage | null;
  selectedCategory?: DebtCategory | null;
  onSelectCategory?: (category: DebtCategory | null) => void;
}

const CATEGORY_META: Record<
  DebtCategory,
  { title: string; icon: React.ComponentType<{ className?: string }> }
> = {
  error_handling: { title: "Error handling debt", icon: AlertTriangle },
  authentication_consistency: { title: "Authentication consistency", icon: KeyRound },
  authorization_consistency: { title: "Authorization consistency", icon: ShieldCheck },
  input_validation: { title: "Input validation debt", icon: CheckSquare },
  logging_and_secrets: { title: "Logging & secret hygiene", icon: FileText },
  code_duplication: { title: "Duplication & boilerplate", icon: Copy },
  architectural_consistency: { title: "Architectural consistency", icon: Layers },
};

export function CategoryMatrix({
  categories,
  coverage,
  selectedCategory,
  onSelectCategory,
}: CategoryMatrixProps) {
  const frameworks = coverage?.detected_frameworks || [];
  const unsupported = coverage?.unsupported_frameworks || [];
  const routesCount = coverage?.total_routes_detected ?? 0;

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
            <span>Architectural debt categories</span>
          </h2>
          <p className="text-xs text-ink-400 mt-0.5">
            Categories with implemented analyzers contribute to the score.
          </p>

          {/* Framework-level coverage indicator */}
          {(frameworks.length > 0 || unsupported.length > 0 || routesCount > 0) && (
            <div className="flex flex-wrap items-center gap-2 mt-2 pt-2 border-t border-border">
              <span className="text-[11px] font-mono text-ink-400 flex items-center gap-1">
                <Globe className="h-3 w-3 text-ink-400" />
                Frameworks:
              </span>
              {frameworks.length > 0 ? (
                frameworks.map((fw) => (
                  <span
                    key={fw}
                    className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-ink-800 border border-border text-ink-200"
                  >
                    {fw}
                  </span>
                ))
              ) : (
                <span className="text-[11px] font-mono text-ink-500 italic">None detected</span>
              )}

              {unsupported.map((fw) => (
                <span
                  key={fw}
                  className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-ink-800 border border-border text-amber-300"
                >
                  {fw} (unsupported)
                </span>
              ))}

              <span className="text-[11px] font-mono text-ink-400 ml-auto flex items-center gap-1">
                <Radio className="h-2.5 w-2.5 text-red-400" />
                Routes: {routesCount}
              </span>
            </div>
          )}
        </div>
        {selectedCategory && (
          <button
            onClick={() => onSelectCategory && onSelectCategory(null)}
            className="text-xs text-ink-300 hover:text-white transition-colors font-mono"
          >
            Clear filter
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {Object.entries(categories).map(([key, breakdown]) => {
          const categoryKey = key as DebtCategory;
          const meta = CATEGORY_META[categoryKey];
          const Icon = meta ? meta.icon : Layers;
          const isSelected = selectedCategory === categoryKey;
          const isAnalyzed = breakdown.status === "analyzed";

          return (
            <div
              key={categoryKey}
              onClick={() => {
                if (isAnalyzed && onSelectCategory) {
                  onSelectCategory(isSelected ? null : categoryKey);
                }
              }}
              className={`p-4 rounded-lg border transition-colors bg-card ${
                isAnalyzed
                  ? "cursor-pointer hover:border-ink-600"
                  : "opacity-60 cursor-default"
              } ${
                isSelected
                  ? "border-red-500/80 bg-ink-850"
                  : "border-border"
              }`}
            >
              {/* Header with status badge */}
              <div className="flex items-center justify-between">
                <div className="h-7 w-7 rounded-md bg-ink-800 border border-border flex items-center justify-center text-ink-300">
                  <Icon className="h-3.5 w-3.5" />
                </div>

                <div className="text-right">
                  {isAnalyzed && breakdown.score !== null ? (
                    <div>
                      <span className="text-base font-semibold font-mono tabular-nums text-white">
                        {breakdown.score}
                      </span>
                      <span className="text-[11px] text-ink-500 ml-0.5 font-mono">/100</span>
                    </div>
                  ) : (
                    <span className="text-xs font-mono text-ink-500">—</span>
                  )}
                </div>
              </div>

              <div className="mt-3">
                <h3 className="text-xs font-medium text-white tracking-tight truncate">
                  {meta ? meta.title : categoryKey}
                </h3>

                <div className="flex items-center gap-1.5 mt-1.5 text-xs">
                  {isAnalyzed ? (
                    <span className="text-[11px] text-ink-400 font-mono">
                      {breakdown.finding_count} finding{breakdown.finding_count !== 1 ? "s" : ""}
                    </span>
                  ) : (
                    <span className="text-[11px] text-ink-500 font-mono flex items-center gap-1">
                      <Clock className="h-2.5 w-2.5 text-ink-500" />
                      <span>Not analyzed</span>
                    </span>
                  )}
                </div>
              </div>

              {/* Progress track */}
              <div className="w-full h-1 bg-ink-800 rounded-full mt-3 overflow-hidden">
                <div
                  className="h-full bg-ink-400 transition-all duration-300"
                  style={{
                    width:
                      isAnalyzed && breakdown.score !== null
                        ? `${Math.max(breakdown.score > 0 ? 4 : 0, breakdown.score)}%`
                        : "0%",
                  }}
                />
              </div>

              {/* Description & Status text */}
              <div className="mt-2 text-[11px] text-ink-400 leading-tight">
                {isAnalyzed ? (
                  <span>
                    Base weight: {(breakdown.weight * 100).toFixed(0)}%
                  </span>
                ) : (
                  <span className="text-ink-500 italic">
                    {breakdown.explanation || "No supported files"}
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

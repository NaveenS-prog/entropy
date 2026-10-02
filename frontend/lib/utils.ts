import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { DebtCategory, DebtScoreTier, Severity } from "@/types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function getTierColor(tier: DebtScoreTier): {
  bg: string;
  text: string;
  border: string;
  bar: string;
} {
  switch (tier) {
    case "very_low":
      return {
        bg: "bg-emerald-500/10",
        text: "text-emerald-400",
        border: "border-emerald-500/30",
        bar: "bg-emerald-500",
      };
    case "low":
      return {
        bg: "bg-cyan-500/10",
        text: "text-cyan-400",
        border: "border-cyan-500/30",
        bar: "bg-cyan-500",
      };
    case "moderate":
      return {
        bg: "bg-amber-500/10",
        text: "text-amber-400",
        border: "border-amber-500/30",
        bar: "bg-amber-500",
      };
    case "high":
      return {
        bg: "bg-orange-500/10",
        text: "text-orange-400",
        border: "border-orange-500/30",
        bar: "bg-orange-500",
      };
    case "very_high":
      return {
        bg: "bg-red-500/10",
        text: "text-red-400",
        border: "border-red-500/30",
        bar: "bg-red-500",
      };
  }
}

export function getSeverityBadge(severity: Severity): {
  bg: string;
  text: string;
  border: string;
} {
  switch (severity) {
    case "critical":
      return { bg: "bg-red-500/20", text: "text-red-400", border: "border-red-500/40" };
    case "high":
      return { bg: "bg-orange-500/20", text: "text-orange-400", border: "border-orange-500/40" };
    case "medium":
      return { bg: "bg-amber-500/20", text: "text-amber-400", border: "border-amber-500/40" };
    case "low":
      return { bg: "bg-blue-500/20", text: "text-blue-400", border: "border-blue-500/40" };
    case "info":
      return { bg: "bg-slate-500/20", text: "text-slate-400", border: "border-slate-500/40" };
  }
}

export function getSeverityColor(severity: Severity): string {
  const badge = getSeverityBadge(severity);
  return `${badge.bg} ${badge.text} ${badge.border}`;
}

export function getCategoryDisplayName(category: DebtCategory): string {
  const names: Record<DebtCategory, string> = {
    error_handling: "Error Handling Debt",
    authentication_consistency: "Authentication Consistency Debt",
    authorization_consistency: "Authorization Consistency Debt",
    input_validation: "Input Validation Debt",
    logging_and_secrets: "Logging & Secret-Handling Debt",
    code_duplication: "Duplication & Boilerplate Debt",
    architectural_consistency: "Architectural Consistency Debt",
  };
  return names[category] || category;
}


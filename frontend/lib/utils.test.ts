import { describe, it, expect } from "vitest";
import { getTierColor, getSeverityBadge, getCategoryDisplayName } from "./utils";

describe("Frontend Utility Tests", () => {
  it("maps debt score tiers to correct color schemes", () => {
    const veryLow = getTierColor("very_low");
    expect(veryLow.text).toBe("text-emerald-400");

    const high = getTierColor("high");
    expect(high.text).toBe("text-orange-400");

    const veryHigh = getTierColor("very_high");
    expect(veryHigh.text).toBe("text-red-400");
  });

  it("maps finding severities to badge styles", () => {
    const crit = getSeverityBadge("critical");
    expect(crit.text).toBe("text-red-400");

    const med = getSeverityBadge("medium");
    expect(med.text).toBe("text-amber-400");

    const info = getSeverityBadge("info");
    expect(info.text).toBe("text-slate-400");
  });

  it("maps debt categories to human-readable names", () => {
    expect(getCategoryDisplayName("error_handling")).toBe("Error Handling Debt");
    expect(getCategoryDisplayName("authentication_consistency")).toBe("Authentication Consistency Debt");
    expect(getCategoryDisplayName("authorization_consistency")).toBe("Authorization Consistency Debt");
  });
});

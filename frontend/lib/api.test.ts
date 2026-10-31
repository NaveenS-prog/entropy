import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { requestAIExplanation, explainFinding, getRefactoringSuggestion } from "./api";
import { DEMO_AI_EXPLANATIONS } from "./demoData";

describe("AI Explanation API Client", () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it("returns pre-cached grounded explanation for demo scan findings without network overhead", async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock;

    const explanation = await requestAIExplanation("finding-demo-01", "demo-forensic-scan-01");

    expect(fetchMock).not.toHaveBeenCalled();
    expect(explanation).toBeDefined();
    expect(explanation.finding_id).toBe("finding-demo-01");
    expect(explanation.summary).toContain("/invoices/export");
    expect(explanation.disclaimer).toBe(
      "AI-generated explanation — advisory only. Does not alter deterministic findings or scores."
    );
  });

  it("falls back to demo explanation when backend fetch fails with network error", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("Network connection refused"));

    const explanation = await requestAIExplanation("finding-demo-02", "scan-999");

    expect(explanation).toBeDefined();
    expect(explanation.finding_id).toBe("finding-demo-02");
    expect(explanation.summary).toContain("PaymentProcessor");
    expect(explanation.disclaimer).toBe(
      "AI-generated explanation — advisory only. Does not alter deterministic findings or scores."
    );
  });

  it("throws error when backend fetch fails for an unknown non-demo finding", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      statusText: "Not Found",
      json: async () => ({ detail: "Finding not found" }),
    });

    await expect(requestAIExplanation("finding-unknown-999", "scan-123")).rejects.toThrow(
      "Finding not found"
    );
  });

  it("parses successful backend AI explanation response", async () => {
    const mockBackendExplanation = {
      finding_id: "finding-real-123",
      summary: "Detected missing auth guard on internal route",
      why_it_matters: "May allow privilege escalation",
      evidence_explanation: "AST node CallExpression at line 42",
      architectural_impact: "Perimeter boundary leak",
      remediation: "Add auth middleware to router chain",
      suggested_pattern: "router.use(authMiddleware)",
      confidence: "high",
      generated_at: "2026-10-31T12:00:00Z",
      model: "gpt-4o-mini",
      prompt_version: "1",
      disclaimer: "AI-generated explanation — advisory only. Does not alter deterministic findings or scores.",
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockBackendExplanation,
    });

    const result = await requestAIExplanation("finding-real-123", "scan-123");

    expect(result.finding_id).toBe("finding-real-123");
    expect(result.model).toBe("gpt-4o-mini");
    expect(result.disclaimer).toContain("advisory only");
  });

  it("resolves deterministic baseline explanation for demo findings", async () => {
    const baseline = await explainFinding("demo-forensic-scan-01", "finding-demo-01");
    expect(baseline.finding_id).toBe("finding-demo-01");
    expect(baseline.architectural_context).toContain("Route handler /invoices/export");
    expect(baseline.maintenance_risk).toBeDefined();
    expect(baseline.suggested_action).toBeDefined();
  });

  it("resolves demo refactoring suggestion with AST pattern and rationale", async () => {
    const refactor = await getRefactoringSuggestion("demo-forensic-scan-01", "finding-demo-01");
    expect(refactor.finding_id).toBe("finding-demo-01");
    expect(refactor.suggested_code).toContain("router.get");
    expect(refactor.rationale).toBeDefined();
  });
});

"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldAlert,
  Sparkles,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  Copy,
  Layers,
  Network,
  Bug,
  Activity,
  Terminal,
  Zap,
  Play,
  RotateCcw,
  Check,
} from "lucide-react";
import { EntropyMeshCanvas } from "./EntropyMeshCanvas";

interface EntropyExplainerHeroProps {
  onStartScanClick: () => void;
  onLoadDemoSample: () => void;
  isBackendConnected: boolean;
}

export function EntropyExplainerHero({
  onStartScanClick,
  onLoadDemoSample,
  isBackendConnected,
}: EntropyExplainerHeroProps) {
  const [activeComparisonTab, setActiveComparisonTab] = useState<"illusion" | "reality">("reality");
  const [activeDimension, setActiveDimension] = useState<number>(0);
  const [copiedCode, setCopiedCode] = useState(false);

  const dimensions = [
    {
      id: "perimeter",
      title: "Perimeter & Auth Drift",
      badge: "High Risk",
      badgeColor: "text-amber-400 bg-amber-950/60 border-amber-800/60",
      icon: ShieldAlert,
      metric: "72% of AI APIs leak unprotected routes",
      desc: "AI code generators write individual route handlers in isolation. While route /orders has auth middleware, route /orders/export generated 5 minutes later omits the dependency injection guard entirely.",
      codePreview: `// AI-Generated Router (File A vs File B)
// routes/users.ts -> Protected
router.get("/profile", requireAuth, getUserProfile);

// routes/billing.ts -> Copilot created without middleware!
router.get("/invoices/export", exportInvoices); // ⚠️ ZERO AUTH GUARD!`,
    },
    {
      id: "duplication",
      title: "AST Structural Duplication",
      badge: "Maintenance Sink",
      badgeColor: "text-cyan-400 bg-cyan-950/60 border-cyan-800/60",
      icon: Copy,
      metric: "Up to 4.2x duplicate AST subtrees",
      desc: "Instead of modular abstractions, AI developers prompt for new features and receive 90% identical syntax with different local variable names. Traditional token hashing misses this, but Entropy's AST normalizer catches it deterministically.",
      codePreview: `// Normalized AST Tree match detected
// controllers/payment.py & controllers/refund.py
// Identical AST structure (ENT-DUP-001)
def process_refund(tx_id, user_ctx):
    verified = check_perm(user_ctx)
    if not verified: return False
    return gateway.send(tx_id, Action.REFUND)`,
    },
    {
      id: "errors",
      title: "Error Boundary Erosion",
      badge: "Silent Failure",
      badgeColor: "text-rose-400 bg-rose-950/60 border-rose-800/60",
      icon: AlertTriangle,
      metric: "Silent exception swallowing in 61% repos",
      desc: "To make unit tests pass, AI generators frequently catch broad Exceptions and return fallback defaults (or empty pass), concealing database crashes, corrupted states, and security anomalies from observability tools.",
      codePreview: `try:
    auth_token = verify_upstream_jwks(token_str)
except Exception:
    # ⚠️ AI fallback: Silently passes to avoid test failure!
    auth_token = None # Silent erosion`,
    },
    {
      id: "framework",
      title: "Framework Inconsistency",
      badge: "Architectural Debt",
      badgeColor: "text-purple-400 bg-purple-950/60 border-purple-800/60",
      icon: Layers,
      metric: "Mixed async/sync & inconsistent pipelines",
      desc: "Large codebases accumulate competing paradigms: raw SQLite queries mixed with SQLAlchemy ORM, raw Express callbacks mixed with Next.js App Router server actions.",
      codePreview: `// Mixing synchronous blocking fs calls inside async high-throughput loop
const data = await fetchPendingJobs();
data.forEach(job => {
  fs.readFileSync(job.configPath); // ⚠️ Thread starvation!
});`,
    },
    {
      id: "topology",
      title: "Topology & Cyclic Coupling",
      badge: "System Fragility",
      badgeColor: "text-emerald-400 bg-emerald-950/60 border-emerald-800/60",
      icon: Network,
      metric: "Circular dependencies & tight coupling",
      desc: "AI prompts lack holistic topological awareness. Prompting for cross-domain features introduces circular imports and unmanaged dependency cascades between unrelated domain modules.",
      codePreview: `// auth/service.ts imports billing/receipt.ts
// billing/receipt.ts imports auth/service.ts
// ENT-ARCH-001: Cyclic dependency graph cycle detected`,
    },
  ];

  const handleCopyCode = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  return (
    <div className="relative overflow-hidden rounded-2xl border border-border/80 bg-ink-950 shadow-2xl mb-8">
      {/* Background Interactive Mesh Canvas */}
      <EntropyMeshCanvas />

      {/* Radial overlay gradient */}
      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-ink-950/70 to-ink-950 pointer-events-none" />

      {/* Content wrapper */}
      <div className="relative z-10 px-6 py-10 md:px-12 md:py-14 space-y-10">
        {/* Top Eyebrow & Badges */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 text-xs font-mono font-medium tracking-wide shadow-glow-emerald"
          >
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span>FORENSIC ARCHITECTURAL SECURITY DEBT ENGINE</span>
          </motion.div>

          <div className="flex items-center gap-2 text-xs font-mono text-ink-400">
            <span className="px-2 py-0.5 rounded bg-ink-850 border border-border text-ink-300">
              Python 3.11+ &amp; JS/TS AST
            </span>
            <span className="px-2 py-0.5 rounded bg-ink-850 border border-border text-ink-300">
              Deterministic Math
            </span>
          </div>
        </div>

        {/* Main Hero Header */}
        <div className="max-w-4xl space-y-5">
          <motion.h1
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1, duration: 0.6 }}
            className="text-3xl md:text-5xl font-extrabold tracking-tight text-white leading-tight"
          >
            Code generated by AI looks pristine.{" "}
            <span className="text-gradient-entropy">
              Until its architecture collapses.
            </span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2, duration: 0.6 }}
            className="text-base md:text-lg text-ink-300 leading-relaxed max-w-3xl font-normal"
          >
            Traditional SAST scans for line-level syntax vulnerabilities (CVEs and SQL injections).{" "}
            <strong className="text-white font-semibold">Entropy</strong> uncovers what linters miss:
            the compounding structural decay, perimeter auth drift, copy-paste AST duplication, and
            eroded error boundaries introduced when building fast with Copilot, Cursor, and LLMs.
          </motion.p>
        </div>

        {/* Call-to-action bar */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3, duration: 0.6 }}
          className="flex flex-wrap items-center gap-4 pt-2"
        >
          <button
            onClick={onStartScanClick}
            className="group flex items-center gap-2.5 px-6 py-3 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-ink-950 font-bold text-sm tracking-wide shadow-glow-emerald transition-all duration-300 hover:scale-[1.02] active:scale-[0.98]"
          >
            <Play className="h-4 w-4 fill-ink-950 transition-transform group-hover:translate-x-0.5" />
            <span>Scan Your Repository</span>
            <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
          </button>

          <button
            onClick={onLoadDemoSample}
            className="flex items-center gap-2 px-5 py-3 rounded-xl bg-ink-850 hover:bg-ink-800 border border-border/90 hover:border-ink-500 text-white font-medium text-sm transition-all duration-200"
          >
            <Sparkles className="h-4 w-4 text-cyan-400" />
            <span>Load Sample Forensic Audit</span>
          </button>

          <div className="flex items-center gap-2 text-xs text-ink-400 font-mono ml-auto">
            <span className="h-2 w-2 rounded-full bg-emerald-400"></span>
            <span>Zero untrusted execution</span>
            <span className="text-ink-600">•</span>
            <span>Hermetic AST verification</span>
          </div>
        </motion.div>

        {/* Stats Row */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.4 }}
          className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-4 border-t border-border/80"
        >
          {[
            {
              label: "Deterministic Analysis",
              value: "100% AST Grounded",
              sub: "Zero LLM hallucinations",
            },
            {
              label: "Perimeter Verification",
              value: "Sub-Route Scoping",
              sub: "Express, FastAPI, Next.js",
            },
            {
              label: "Audit Traceability",
              value: "Math-Explainable",
              sub: "Step-by-step point ledger",
            },
            {
              label: "Scan Throughput",
              value: "< 1.4s Cold Run",
              sub: "Parallel AST normalizers",
            },
          ].map((stat, i) => (
            <div
              key={i}
              className="p-3.5 rounded-xl bg-ink-900/60 border border-border/60 backdrop-blur-md"
            >
              <div className="text-[11px] font-mono text-ink-400 uppercase tracking-wider">
                {stat.label}
              </div>
              <div className="text-base font-bold text-white mt-1">{stat.value}</div>
              <div className="text-xs text-emerald-400/90 font-mono mt-0.5">{stat.sub}</div>
            </div>
          ))}
        </motion.div>

        {/* Interactive Feature 1: The Illusion vs Reality Comparison */}
        <div className="space-y-4 pt-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold uppercase tracking-wider text-ink-200 flex items-center gap-2">
                <Zap className="h-4 w-4 text-amber-400" />
                <span>The Core Dilemma: What Linters Miss vs What Entropy Catches</span>
              </h3>
              <p className="text-xs text-ink-400 mt-0.5">
                Toggle between traditional scanner output and Entropy&apos;s architectural audit.
              </p>
            </div>

            {/* Segmented Switcher */}
            <div className="inline-flex rounded-lg bg-ink-900 p-1 border border-border self-start">
              <button
                onClick={() => setActiveComparisonTab("illusion")}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                  activeComparisonTab === "illusion"
                    ? "bg-ink-800 text-white shadow-sm"
                    : "text-ink-400 hover:text-white"
                }`}
              >
                <span>Traditional SAST (Passed)</span>
              </button>
              <button
                onClick={() => setActiveComparisonTab("reality")}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                  activeComparisonTab === "reality"
                    ? "bg-rose-950/70 text-rose-300 border border-rose-800/80 shadow-glow-amber"
                    : "text-ink-400 hover:text-white"
                }`}
              >
                <AlertTriangle className="h-3.5 w-3.5 text-rose-400" />
                <span>Entropy AST Reality (High Debt)</span>
              </button>
            </div>
          </div>

          <AnimatePresence mode="wait">
            {activeComparisonTab === "illusion" ? (
              <motion.div
                key="illusion"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.25 }}
                className="grid grid-cols-1 md:grid-cols-2 gap-4 p-5 rounded-xl bg-ink-900/80 border border-border backdrop-blur-md"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
                      <CheckCircle2 className="h-4 w-4" />
                      Standard Linter / SAST Tool: PASS
                    </span>
                    <span className="text-[11px] font-mono text-ink-400">0 Alerts</span>
                  </div>
                  <p className="text-xs text-ink-300 leading-relaxed">
                    Copilot generated 3 separate API handlers. Because every variable has a type and
                    there are no raw string interpolations in SQL, traditional scanners give a green
                    check.
                  </p>
                  <div className="p-3 rounded-lg bg-ink-950 border border-border text-[11px] font-mono text-emerald-400 space-y-1">
                    <div>✓ ESLint: 0 errors, 0 warnings</div>
                    <div>✓ SonarQube: 0 vulnerabilities (A-grade)</div>
                    <div>✓ Unit tests: 14/14 passing</div>
                  </div>
                </div>

                <div className="relative p-3.5 rounded-lg bg-ink-950 border border-border font-mono text-xs text-ink-300 overflow-x-auto">
                  <div className="text-[11px] text-ink-500 mb-2 border-b border-border/60 pb-1">
                    routes/billing_export.ts
                  </div>
                  <pre className="text-ink-300 leading-relaxed text-[11px]">
{`export async function handleBillingExport(req, res) {
  // Syntactically valid, clean looking handler
  const { organizationId } = req.query;
  const records = await db.invoices.find({ org: organizationId });
  return res.json({ status: "success", data: records });
}`}
                  </pre>
                  <div className="mt-2 text-[10px] text-amber-400 bg-amber-950/30 p-2 rounded border border-amber-900/40">
                    Looks harmless in isolation. But in context of the whole app, it completely bypasses the auth guard used by all other billing routes!
                  </div>
                </div>
              </motion.div>
            ) : (
              <motion.div
                key="reality"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.25 }}
                className="grid grid-cols-1 md:grid-cols-2 gap-4 p-5 rounded-xl bg-ink-900/80 border border-rose-900/40 backdrop-blur-md"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono text-rose-400 flex items-center gap-1.5 font-bold">
                      <AlertTriangle className="h-4 w-4" />
                      Entropy AST Engine: ARCHITECTURAL ANOMALY DETECTED
                    </span>
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800">
                      Score: 54/100 (High Risk)
                    </span>
                  </div>
                  <p className="text-xs text-ink-300 leading-relaxed">
                    Entropy maps the whole-repository topology. It flagged that{" "}
                    <code className="text-white">/invoices/export</code> lacks the{" "}
                    <code className="text-emerald-400">verifyOrgTenant</code> middleware present on
                    11 sibling routes in <code className="text-white">routes/billing.ts</code>.
                  </p>
                  <div className="space-y-1.5 text-xs font-mono">
                    <div className="flex items-center justify-between p-2 rounded bg-ink-950 border border-border">
                      <span className="text-rose-400">ENT-SEC-002: Perimeter Auth Drift</span>
                      <span className="text-rose-400 font-bold">-18 pts</span>
                    </div>
                    <div className="flex items-center justify-between p-2 rounded bg-ink-950 border border-border">
                      <span className="text-amber-400">ENT-DUP-001: 87% AST Structural Duplication</span>
                      <span className="text-amber-400 font-bold">-12 pts</span>
                    </div>
                  </div>
                </div>

                <div className="relative p-3.5 rounded-lg bg-ink-950 border border-rose-900/50 font-mono text-xs overflow-x-auto">
                  <div className="flex items-center justify-between text-[11px] text-ink-500 mb-2 border-b border-border/60 pb-1">
                    <span>Cross-file Architectural Diff</span>
                    <span className="text-rose-400">ENT-SEC-002</span>
                  </div>
                  <pre className="text-[11px] leading-relaxed">
{`// routes/billing.ts (Standard convention)
router.get("/invoices", `}<span className="text-emerald-400 font-bold">{`[verifyOrgTenant, requireAuth]`}</span>{`, getInvoices);

// routes/billing_export.ts (AI Hallucinated shortcut)
router.get("/invoices/export", `}<span className="text-rose-400 font-bold bg-rose-950/60 px-1">{`/* MISSING MIDDLEWARE! */`}</span>{`, handleBillingExport);`}
                  </pre>
                  <div className="mt-2 text-[10px] text-emerald-300 bg-emerald-950/30 p-2 rounded border border-emerald-900/40">
                    Entropy flags structural inconsistency without needing human code review or tests.
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Interactive Feature 2: The 5 Dimensions of Architectural Debt */}
        <div className="space-y-4 pt-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold uppercase tracking-wider text-ink-200 flex items-center gap-2">
                <Layers className="h-4 w-4 text-emerald-400" />
                <span>The 5 Architectural Debt Dimensions</span>
              </h3>
              <p className="text-xs text-ink-400 mt-0.5">
                Click any pillar to inspect the forensic detection vector and live AST pattern.
              </p>
            </div>
            <span className="text-xs font-mono text-ink-500 hidden sm:inline-block">
              Interactive Inspector
            </span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            {/* Dimension selection buttons */}
            <div className="lg:col-span-5 space-y-2">
              {dimensions.map((dim, idx) => {
                const Icon = dim.icon;
                const isSelected = activeDimension === idx;
                return (
                  <button
                    key={dim.id}
                    onClick={() => setActiveDimension(idx)}
                    className={`w-full text-left p-3.5 rounded-xl border transition-all duration-200 flex items-start gap-3.5 ${
                      isSelected
                        ? "bg-ink-850 border-emerald-500/60 shadow-glow-emerald"
                        : "bg-ink-900/70 border-border/80 hover:bg-ink-850 hover:border-ink-600"
                    }`}
                  >
                    <div
                      className={`h-9 w-9 rounded-lg flex items-center justify-center shrink-0 ${
                        isSelected
                          ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                          : "bg-ink-800 text-ink-400 border border-border"
                      }`}
                    >
                      <Icon className="h-4 w-4" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-semibold text-xs text-white truncate">
                          {dim.title}
                        </span>
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded border ${dim.badgeColor}`}
                        >
                          {dim.badge}
                        </span>
                      </div>
                      <p className="text-[11px] text-ink-400 mt-1 line-clamp-1">{dim.metric}</p>
                    </div>
                  </button>
                );
              })}
            </div>

            {/* Active dimension detail panel */}
            <div className="lg:col-span-7 bg-ink-900/90 border border-border rounded-xl p-5 flex flex-col justify-between space-y-4 backdrop-blur-md">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-white">
                      {dimensions[activeDimension].title}
                    </span>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded border ${dimensions[activeDimension].badgeColor}`}
                    >
                      {dimensions[activeDimension].metric}
                    </span>
                  </div>

                  <button
                    onClick={() => handleCopyCode(dimensions[activeDimension].codePreview)}
                    className="flex items-center gap-1 text-[11px] font-mono text-ink-400 hover:text-white px-2 py-1 rounded bg-ink-850 border border-border transition-colors"
                  >
                    {copiedCode ? (
                      <>
                        <Check className="h-3 w-3 text-emerald-400" />
                        <span className="text-emerald-400">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3 w-3" />
                        <span>Copy snippet</span>
                      </>
                    )}
                  </button>
                </div>

                <p className="text-xs text-ink-300 leading-relaxed">
                  {dimensions[activeDimension].desc}
                </p>

                <div className="rounded-lg bg-ink-950 border border-border p-3.5 font-mono text-xs overflow-x-auto">
                  <pre className="text-[11px] text-ink-200 leading-relaxed">
                    {dimensions[activeDimension].codePreview}
                  </pre>
                </div>
              </div>

              <div className="flex items-center justify-between pt-3 border-t border-border/80 text-xs font-mono text-ink-400">
                <span>Vector: {dimensions[activeDimension].id.toUpperCase()}</span>
                <span className="text-emerald-400 flex items-center gap-1">
                  <Activity className="h-3.5 w-3.5" />
                  Deterministic AST Extraction
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

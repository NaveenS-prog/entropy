import {
  AIExplanation,
  DebtScoreResult,
  Finding,
  RepositoryManifest,
  RepositoryScanResult,
} from "@/types";

export const DEMO_SCAN_RESULT: RepositoryScanResult = {
  scan_id: "demo-forensic-scan-01",
  repo_path: "github.com/cloud-mesh/enterprise-ai-service",
  repo_name: "enterprise-ai-service (Forensic Sample)",
  repository: {
    name: "enterprise-ai-service (Forensic Sample)",
    path: "github.com/cloud-mesh/enterprise-ai-service",
    repository_id: "repo-demo-01",
    branch: "main",
    total_files: 42,
    scannable_files: 38,
    total_loc: 6420,
  },
  status: "completed",
  started_at: "2026-10-31T10:00:00.000Z",
  completed_at: "2026-10-31T10:00:01.240Z",
  duration_ms: 1240,
  findings: [],
  analyzers_executed: [
    "structural_duplication",
    "perimeter_auth_drift",
    "error_boundary_erosion",
    "input_validation_analyzer",
    "cyclical_topology_analyzer",
  ],
  errors: [],
};

export const DEMO_SCORE_RESULT: DebtScoreResult = {
  total_score: 64,
  score_density: 9.97,
  severity_floor_applied: true,
  floor_reason: "High severity perimeter authentication drift detected in critical router.",
  worst_category: {
    name: "Authentication & Perimeter",
    score: 42,
  },
  entropy_score: 36,
  tier: "moderate",
  total_findings: 4,
  total_loc: 6420,
  analyzed_files: 38,
  skipped_files: 0,
  formula_summary: "Deterministic AST analysis normalized over 6.42 KLOC with diminishing returns scaling.",
  audit_trail: [
    "Scanned 38 source files across TypeScript (24), Python (12), Go (2).",
    "AST normalized: 142 AST subtrees inspected for structural duplication.",
    "Perimeter analyzer detected 1 unauthenticated edge route (/invoices/export).",
    "Severity floor applied: High-severity finding bounded headline score to 64/100.",
  ],
  is_explainable: true,
  category_scores: {
    authentication_consistency: {
      category: "authentication_consistency",
      status: "analyzed",
      score: 42,
      finding_count: 1,
      severity_counts: { info: 0, low: 0, medium: 0, high: 1, critical: 0 },
      weight: 0.3,
      weighted_score: 12.6,
      raw_deduction: 58,
      explanation: "Isolated AI-generated export endpoints bypass the centralized auth middleware chain.",
      top_rules: [
        {
          rule_id: "ENT-SEC-002",
          rule_title: "Perimeter Auth Bypass Drift",
          finding_count: 1,
          weighted_points: 35,
        },
      ],
    },
    code_duplication: {
      category: "code_duplication",
      status: "analyzed",
      score: 55,
      finding_count: 1,
      severity_counts: { info: 0, low: 0, medium: 1, high: 0, critical: 0 },
      weight: 0.25,
      weighted_score: 13.75,
      raw_deduction: 45,
      explanation: "Substantial AST clone-and-modify antipatterns across payment & refund handler pipelines.",
      top_rules: [
        {
          rule_id: "ENT-DUP-001",
          rule_title: "Identical AST Subtree Clone",
          finding_count: 1,
          weighted_points: 25,
        },
      ],
    },
    error_handling: {
      category: "error_handling",
      status: "analyzed",
      score: 68,
      finding_count: 1,
      severity_counts: { info: 0, low: 0, medium: 1, high: 0, critical: 0 },
      weight: 0.2,
      weighted_score: 13.6,
      raw_deduction: 32,
      explanation: "Silenced generic exceptions returning null fallbacks, concealing downstream database timeouts.",
    },
    input_validation: {
      category: "input_validation",
      status: "analyzed",
      score: 82,
      finding_count: 0,
      severity_counts: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
      weight: 0.15,
      weighted_score: 12.3,
      raw_deduction: 18,
      explanation: "Standard input sanitization observed across majority of validated endpoints.",
    },
    logging_and_secrets: {
      category: "logging_and_secrets",
      status: "analyzed",
      score: 90,
      finding_count: 0,
      severity_counts: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
      weight: 0.1,
      weighted_score: 9.0,
      raw_deduction: 10,
      explanation: "Zero plaintext API credentials or tokens found in analyzed AST string constants.",
    },
    authorization_consistency: {
      category: "authorization_consistency",
      status: "analyzed",
      score: 75,
      finding_count: 0,
      severity_counts: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
      weight: 0.15,
      weighted_score: 11.25,
      raw_deduction: 25,
      explanation: "Role-based access controls mapped across internal domain services.",
    },
    architectural_consistency: {
      category: "architectural_consistency",
      status: "analyzed",
      score: 72,
      finding_count: 1,
      severity_counts: { info: 0, low: 1, medium: 0, high: 0, critical: 0 },
      weight: 0.1,
      weighted_score: 7.2,
      raw_deduction: 28,
      explanation: "Cyclic dependency graph between user and account verification domain modules.",
    },
  },
  coverage: {
    categories: {
      error_handling: {
        category: "error_handling",
        status: "analyzed",
        supported_languages: ["typescript", "python"],
        present_languages: ["typescript", "python", "go"],
        is_analyzed: true,
      },
      authentication_consistency: {
        category: "authentication_consistency",
        status: "analyzed",
        supported_languages: ["typescript", "python"],
        present_languages: ["typescript", "python", "go"],
        is_analyzed: true,
      },
      authorization_consistency: {
        category: "authorization_consistency",
        status: "analyzed",
        supported_languages: ["typescript", "python"],
        present_languages: ["typescript", "python", "go"],
        is_analyzed: true,
      },
      input_validation: {
        category: "input_validation",
        status: "analyzed",
        supported_languages: ["typescript", "python"],
        present_languages: ["typescript", "python", "go"],
        is_analyzed: true,
      },
      logging_and_secrets: {
        category: "logging_and_secrets",
        status: "analyzed",
        supported_languages: ["typescript", "python"],
        present_languages: ["typescript", "python", "go"],
        is_analyzed: true,
      },
      code_duplication: {
        category: "code_duplication",
        status: "analyzed",
        supported_languages: ["typescript", "python", "go"],
        present_languages: ["typescript", "python", "go"],
        is_analyzed: true,
      },
      architectural_consistency: {
        category: "architectural_consistency",
        status: "analyzed",
        supported_languages: ["typescript", "python"],
        present_languages: ["typescript", "python", "go"],
        is_analyzed: true,
      },
    },
    present_languages: ["typescript", "python", "go"],
    supported_languages: ["typescript", "python"],
    total_loc: 6420,
    covered_loc: 6240,
    loc_coverage_percentage: 97.2,
    is_partial: false,
    detected_frameworks: ["Express.js", "FastAPI"],
    total_routes_detected: 18,
  },
};


export const DEMO_FINDINGS: Finding[] = [
  {
    id: "finding-demo-01",
    category: "authentication_consistency",
    rule_id: "ENT-SEC-002",
    severity: "high",
    confidence: "high",
    file: "src/api/routes/invoices_export.ts",
    line_start: 14,
    line_end: 26,
    symbol: "exportInvoiceReport",
    title: "Unauthenticated Perimeter Drift on Billing Export",
    description:
      "Route handler /invoices_export does not mount the 'requireAuth' or 'verifyTenantScope' middleware chain enforced on all 11 other sibling endpoints in the billing domain router.",
    evidence: {
      content:
        '// routes/invoices_export.ts\nrouter.get("/invoices/export", async (req: Request, res: Response) => {\n  const { orgId } = req.query;\n  const data = await invoiceService.dumpAll(String(orgId));\n  return res.json(data);\n});',
      line_start: 14,
      line_end: 26,
      highlight_lines: [15, 16],
    },
    impact:
      "High probability of unauthorized multi-tenant data exfiltration through an unshielded edge route created during rapid AI prototyping.",
    recommendation:
      "Mount the standard [requireAuth, verifyTenantScope] middleware array before the export handler callback.",
    fingerprint: "fp-ent-sec-002-invoices-export",
  },
  {
    id: "finding-demo-02",
    category: "code_duplication",
    rule_id: "ENT-DUP-001",
    severity: "medium",
    confidence: "high",
    file: "src/services/subscription_lifecycle.ts",
    line_start: 45,
    line_end: 78,
    symbol: "handleSubscriptionTransition",
    title: "89% AST Structural Clone of PaymentProcessor",
    description:
      "Normalized AST subtree is structurally identical to src/services/payment_orchestrator.ts (lines 102-135). Renaming variable names and comments did not mask the architectural duplication.",
    evidence: {
      content:
        "// src/services/subscription_lifecycle.ts\nasync function handleSubscriptionTransition(subId: string, ctx: UserContext) {\n  const record = await db.subs.findById(subId);\n  if (!record || record.tenantId !== ctx.tenantId) throw new ForbiddenError();\n  const event = buildStripeEvent(record);\n  return await stripeGateway.dispatch(event);\n}",
      line_start: 45,
      line_end: 78,
      highlight_lines: [47, 48, 49],
    },
    impact:
      "Forked business logic leads to inconsistent bugfixes when payment webhook handling changes in one location but remains unpatched in the cloned module.",
    recommendation:
      "Extract the validation and dispatch pipeline into a unified AbstractGatewayDispatcher base class.",
    fingerprint: "fp-ent-dup-001-sub-payment-clone",
  },
  {
    id: "finding-demo-03",
    category: "error_handling",
    rule_id: "ENT-ERR-001",
    severity: "medium",
    confidence: "high",
    file: "backend/auth/token_verifier.py",
    line_start: 32,
    line_end: 42,
    symbol: "verify_external_jwks",
    title: "Silenced Exception Swallowing Authentication Errors",
    description:
      "Broad Exception caught with empty return fallback. Cryptographic validation failures and upstream timeout exceptions are suppressed without structured audit logging.",
    evidence: {
      content:
        'def verify_external_jwks(token_str: str) -> dict | None:\n    try:\n        return jwt.decode(token_str, key=JWKS_CACHE, algorithms=["RS256"])\n    except Exception:\n        # AI generated fallback to avoid 500 error in test cases\n        return None',
      line_start: 32,
      line_end: 42,
      highlight_lines: [35, 36, 37],
    },
    impact:
      "Attacks sending invalid JWT structures fail silently, preventing intrusion detection systems from observing signature probing attempts.",
    recommendation:
      "Explicitly catch PyJWTError, log telemetry with structured request correlation ID, and re-raise or return a typed AuthValidationFailure result.",
    fingerprint: "fp-ent-err-001-jwks-swallowed",
  },
  {
    id: "finding-demo-04",
    category: "architectural_consistency",
    rule_id: "ENT-ARCH-001",
    severity: "low",
    confidence: "high",
    file: "src/domains/accounts/account_service.ts",
    line_start: 8,
    line_end: 22,
    symbol: "AccountService",
    title: "Cross-Domain Cyclic Import Cycle",
    description:
      "AccountService imports UserService, while UserService imports AccountService. Circular topological coupling breaks deterministic module initialization.",
    evidence: {
      content:
        "import { UserService } from '../users/user_service';\n\nexport class AccountService {\n  constructor(private userSvc: UserService) {}\n}",
      line_start: 8,
      line_end: 22,
      highlight_lines: [1, 4],
    },
    impact:
      "Fragile bundler behavior, undefined dependency injection order at runtime, and elevated cognitive load when refactoring.",
    recommendation:
      "Invert dependency via a shared AccountUserEvents contract interface in a shared/ports layer.",
    fingerprint: "fp-ent-arch-001-cyclic-account-user",
  },
];

export const DEMO_MANIFEST: RepositoryManifest = {
  repository: {
    name: "enterprise-ai-service",
    path: "/home/demo/enterprise-ai-service",
    scan_timestamp: new Date().toISOString(),
    total_files: 42,
    source_files: 38,
    ignored_files: 4,
    skipped_files: 0,
    total_source_size: 498210,
    total_source_loc: 6420,
    excluded_files: 2,
    excluded_loc: 180,
  },
  languages: {
    TypeScript: 24,
    Python: 12,
    Go: 2,
  },
  files: [
    {
      path: "src/api/routes/invoices_export.ts",
      language: "typescript",
      size: 1420,
      line_count: 52,
      analysis_supported: true,
    },
    {
      path: "src/services/subscription_lifecycle.ts",
      language: "typescript",
      size: 4210,
      line_count: 140,
      analysis_supported: true,
    },
    {
      path: "backend/auth/token_verifier.py",
      language: "python",
      size: 2890,
      line_count: 98,
      analysis_supported: true,
    },
    {
      path: "src/domains/accounts/account_service.ts",
      language: "typescript",
      size: 3410,
      line_count: 110,
      analysis_supported: true,
    },
    {
      path: "src/api/routes/billing.ts",
      language: "typescript",
      size: 6810,
      line_count: 240,
      analysis_supported: true,
    },
  ],
  skipped_files: [],
};

export const DEMO_AI_EXPLANATIONS: Record<string, AIExplanation> = {
  "finding-demo-01": {
    finding_id: "finding-demo-01",
    summary:
      "Route handler /invoices/export in invoices_export.ts bypasses the organization-wide authentication middleware chain, allowing unauthenticated tenants to trigger invoice dumps.",
    why_it_matters:
      "The billing export endpoint operates as a public route because neither requireAuth nor verifyTenantScope middleware is registered in its pipeline. Because orgId is trusted directly from query parameters without cryptographic identity validation, any anonymous caller can enumerate tenant invoice records.",
    evidence_explanation:
      "Lines 14-26 register router.get('/invoices/export', handler) directly. In contrast, 11 sibling routes in src/api/routes mount the centralized authentication pipeline router.use(requireAuth).",
    architectural_impact:
      "Perimeter drift creates critical security debt. Over time, ad-hoc unauthenticated endpoints increase cross-tenant data leak blast radiuses and violate SOC2/ISO zero-trust boundary invariants.",
    remediation:
      "1. Attach requireAuth and verifyTenantScope middlewares to the endpoint.\n2. Bind orgId strictly from verified session claims (req.user.tenantId) rather than raw user-supplied query parameters.\n3. Add an integration contract test asserting 401 Unauthorized for anonymous callers.",
    suggested_pattern:
      "// Refactored with perimeter guard and tenant scoping\nrouter.get(\n  '/invoices/export',\n  requireAuth,\n  verifyTenantScope,\n  async (req: AuthenticatedRequest, res: Response) => {\n    const tenantId = req.user.tenantId;\n    const data = await invoiceService.dumpForTenant(tenantId);\n    return res.json(data);\n  }\n);",
    confidence: "high",
    generated_at: "2026-10-31T10:05:00.000Z",
    model: "gemini-1.5-flash",
    prompt_version: "1",
    disclaimer:
      "AI-generated explanation — advisory only. Does not alter deterministic findings or scores.",
  },
  "finding-demo-02": {
    finding_id: "finding-demo-02",
    summary:
      "Subscription transition pipeline in subscription_lifecycle.ts duplicates 89% of PaymentProcessor's AST structure instead of composing a unified dispatcher.",
    why_it_matters:
      "Duplicated payment dispatch code causes maintenance bifurcation. Bug fixes and idempotency upgrades applied to payment_orchestrator.ts will not propagate to subscription transitions, leading to silent payment state inconsistencies.",
    evidence_explanation:
      "Lines 45-78 mirror the AST subtree of payment_orchestrator.ts (lines 102-135) with identical state validation, error throwing, event building, and gateway dispatch sequences.",
    architectural_impact:
      "Boilerplate clones increase cognitive overhead during audits and elevate defect density by creating multiple diverging sources of truth for payment gateway interactions.",
    remediation:
      "1. Extract shared payment execution semantics into an AbstractGatewayDispatcher.\n2. Pass specific lifecycle event builders into the unified dispatcher.\n3. Replace the duplicated block with dispatcher.process(event).",
    suggested_pattern:
      "// Unified payment gateway dispatch pattern\nexport async function handleSubscriptionTransition(\n  subId: string,\n  ctx: UserContext\n) {\n  const record = await db.subs.findById(subId);\n  if (!record || record.tenantId !== ctx.tenantId) throw new ForbiddenError();\n  \n  return await paymentDispatcher.dispatch({\n    type: 'SUBSCRIPTION_TRANSITION',\n    tenantId: ctx.tenantId,\n    payload: record,\n  });\n}",
    confidence: "high",
    generated_at: "2026-10-31T10:05:00.000Z",
    model: "gemini-1.5-flash",
    prompt_version: "1",
    disclaimer:
      "AI-generated explanation — advisory only. Does not alter deterministic findings or scores.",
  },
  "finding-demo-03": {
    finding_id: "finding-demo-03",
    summary:
      "Broad Exception catch block in verify_external_jwks swallows token verification errors, masking authentication failure telemetry.",
    why_it_matters:
      "Catching base Exception without logging or differentiating error types suppresses expired key notices, network partition failures, and malformed signature alerts, masquerading attacks as simple missing tokens.",
    evidence_explanation:
      "Lines 32-42 in backend/auth/token_verifier.py wrap jwt.decode in try/except Exception and immediately return None without recording error context or telemetry.",
    architectural_impact:
      "Silenced error boundaries erode audit observability. Security monitoring systems cannot differentiate between a legitimate expired user session and an ongoing cryptographic spoofing attack.",
    remediation:
      "1. Catch PyJWTError specifically rather than generic Exception.\n2. Emit structured warning logs with correlation IDs.\n3. Return a typed result (e.g., Result[TokenClaims, AuthFailureReason]).",
    suggested_pattern:
      "# Explicit error handling with structured logging\nimport jwt\nfrom jwt.exceptions import PyJWTError\nimport logging\n\nlogger = logging.getLogger(__name__)\n\ndef verify_external_jwks(token_str: str) -> dict | None:\n    try:\n        return jwt.decode(token_str, key=JWKS_CACHE, algorithms=['RS256'])\n    except PyJWTError as exc:\n        logger.warning('JWT verification rejected: %s', exc)\n        return None",
    confidence: "high",
    generated_at: "2026-10-31T10:05:00.000Z",
    model: "gemini-1.5-flash",
    prompt_version: "1",
    disclaimer:
      "AI-generated explanation — advisory only. Does not alter deterministic findings or scores.",
  },
  "finding-demo-04": {
    finding_id: "finding-demo-04",
    summary:
      "Circular dependency cycle detected between AccountService and UserService across domain boundaries.",
    why_it_matters:
      "Direct mutual imports prevent tree-shaking, cause undefined runtime evaluation order during startup, and couple account operations with user operations in violation of clean domain boundaries.",
    evidence_explanation:
      "Lines 8-22 in account_service.ts import UserService, while user_service.ts imports AccountService, forming a closed topological loop.",
    architectural_impact:
      "Cyclic coupling makes unit testing difficult by requiring complex mock fixtures and impedes decomposing domains into independent packages or microservices.",
    remediation:
      "1. Introduce a domain event or shared interface in a shared/contracts directory.\n2. Use dependency inversion so both services depend on abstract ports.\n3. Defer circular resolution using event emitters or command handlers.",
    suggested_pattern:
      "// Invert dependency via shared ports\nimport type { UserLookupPort } from '@/shared/ports';\n\nexport class AccountService {\n  constructor(private userLookup: UserLookupPort) {}\n  \n  async resolveAccountUser(accountId: string) {\n    return this.userLookup.getUserForAccount(accountId);\n  }\n}",
    confidence: "high",
    generated_at: "2026-10-31T10:05:00.000Z",
    model: "gemini-1.5-flash",
    prompt_version: "1",
    disclaimer:
      "AI-generated explanation — advisory only. Does not alter deterministic findings or scores.",
  },
};


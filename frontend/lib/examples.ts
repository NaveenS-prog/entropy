import { AIExplanation } from "@/types";

export interface InteractiveAuditPair {
  id: string;
  title: string;
  rule_id: string;
  severity: "critical" | "high" | "medium" | "low";
  category: string;
  fileName: string;
  fileLang: string;
  lineStart: number;
  lineEnd: number;
  codeSnippet: string;
  highlightLines: number[];
  explanation: AIExplanation;
}

export const AUDIT_PAIRS: InteractiveAuditPair[] = [
  {
    id: "pair-1",
    title: "Unauthenticated Route Perimeter Drift",
    rule_id: "ENT-SEC-001",
    severity: "critical",
    category: "Security Perimeter",
    fileName: "src/api/routes/invoices_export.ts",
    fileLang: "typescript",
    lineStart: 12,
    lineEnd: 27,
    highlightLines: [16, 17, 18, 19],
    codeSnippet: `// Invoices billing export controller
import { Router, Request, Response } from "express";
import { invoiceService } from "@/services/invoice";

const router = Router();

// VULNERABLE: Bypasses auth & tenant verification pipeline
router.get("/invoices/export", async (req: Request, res: Response) => {
  const orgId = req.query.orgId as string;
  const invoices = await invoiceService.dumpForTenant(orgId);
  return res.json(invoices);
});

export default router;`,
    explanation: {
      finding_id: "finding-demo-01",
      summary:
        "Route handler /invoices/export bypasses the organization-wide authentication middleware chain, allowing anonymous callers to enumerate tenant invoice archives.",
      why_it_matters:
        "Neither requireAuth nor verifyTenantScope middleware is mounted on this export pipeline. Because orgId is trusted directly from query parameters without cryptographic claim validation, any unauthenticated tenant can exfiltrate financial ledger records.",
      evidence_explanation:
        "Lines 16-19 mount router.get('/invoices/export', handler) directly on the unauthenticated root router, whereas all 11 sibling billing routes attach router.use(requireAuth).",
      architectural_impact:
        "Perimeter drift creates critical security debt. Over time, ad-hoc unprotected endpoints increase cross-tenant data leak blast radiuses and violate SOC2 zero-trust boundary invariants.",
      remediation:
        "1. Attach requireAuth and verifyTenantScope middlewares to the endpoint.\n2. Bind orgId strictly from verified session claims (req.user.tenantId) rather than user-supplied query parameters.\n3. Add an integration contract test asserting 401 Unauthorized for unauthenticated callers.",
      suggested_pattern: `// Refactored with perimeter guard and tenant scoping
router.get(
  "/invoices/export",
  requireAuth,
  verifyTenantScope,
  async (req: AuthenticatedRequest, res: Response) => {
    const tenantId = req.user.tenantId;
    const data = await invoiceService.dumpForTenant(tenantId);
    return res.json(data);
  }
);`,
      confidence: "high",
      generated_at: "2026-10-31T10:05:00.000Z",
      model: "gemini-1.5-flash",
      prompt_version: "1",
      disclaimer:
        "AI-generated explanation — advisory only. Does not alter deterministic findings or scores.",
    },
  },
  {
    id: "pair-2",
    title: "Duplicated Payment Dispatcher Boilerplate",
    rule_id: "ENT-DUP-004",
    severity: "high",
    category: "Boilerplate & Duplication",
    fileName: "src/services/subscription_lifecycle.ts",
    fileLang: "typescript",
    lineStart: 42,
    lineEnd: 60,
    highlightLines: [47, 48, 49, 50, 51, 52, 53, 54],
    codeSnippet: `export async function handleSubscriptionTransition(subId: string, ctx: Context) {
  const sub = await db.subs.findById(subId);
  if (!sub || sub.tenantId !== ctx.tenantId) throw new ForbiddenError();

  // CLONE: 89% duplicated AST structure from payment_orchestrator.ts
  const idempotencyKey = crypto.randomUUID();
  const payload = { amount: sub.planPrice, currency: "usd", account: sub.stripeAccount };
  const gateway = new StripeGateway({ apiKey: process.env.STRIPE_SECRET_KEY });
  const charge = await gateway.charges.create(payload, { idempotencyKey });
  await db.ledger.record({ event: "SUB_CHARGE", chargeId: charge.id });
  return charge;
}`,
    explanation: {
      finding_id: "finding-demo-02",
      summary:
        "Subscription transition pipeline duplicates 89% of PaymentProcessor's AST structure instead of composing a unified payment gateway dispatcher.",
      why_it_matters:
        "Duplicated payment dispatch code causes maintenance bifurcation. Critical bug fixes, retry semantics, and idempotency upgrades applied to payment_orchestrator.ts will not propagate to subscriptions, risking inconsistent billing states.",
      evidence_explanation:
        "Lines 47-54 mirror the AST subtree of payment_orchestrator.ts (lines 102-135) with identical state validation, error throwing, event building, and gateway dispatch sequences.",
      architectural_impact:
        "Boilerplate clones increase cognitive overhead during audits and elevate defect density by creating diverging sources of truth for payment gateway interactions.",
      remediation:
        "1. Extract shared payment execution semantics into an AbstractGatewayDispatcher.\n2. Pass specific lifecycle event builders into the unified dispatcher.\n3. Replace the duplicated block with dispatcher.process(event).",
      suggested_pattern: `// Unified payment gateway dispatch pattern
export async function handleSubscriptionTransition(
  subId: string,
  ctx: UserContext
) {
  const record = await db.subs.findById(subId);
  if (!record || record.tenantId !== ctx.tenantId) throw new ForbiddenError();
  
  return await paymentDispatcher.dispatch({
    type: "SUBSCRIPTION_TRANSITION",
    tenantId: ctx.tenantId,
    payload: record,
  });
}`,
      confidence: "high",
      generated_at: "2026-10-31T10:05:00.000Z",
      model: "gemini-1.5-flash",
      prompt_version: "1",
      disclaimer:
        "AI-generated explanation — advisory only. Does not alter deterministic findings or scores.",
    },
  },
  {
    id: "pair-3",
    title: "Silenced Auth Token Verification Errors",
    rule_id: "ENT-SEC-009",
    severity: "high",
    category: "Security Perimeter",
    fileName: "backend/auth/token_verifier.py",
    fileLang: "python",
    lineStart: 30,
    lineEnd: 44,
    highlightLines: [36, 37, 38, 39],
    codeSnippet: `def verify_external_jwks(token_str: str) -> dict | None:
    """Verify incoming JWT token against cached JWKS keys."""
    try:
        claims = jwt.decode(token_str, key=JWKS_CACHE, algorithms=["RS256"])
        return claims
    except Exception:
        # VULNERABLE: Swallows all exceptions including expired, invalid signature, and network errors
        return None`,
    explanation: {
      finding_id: "finding-demo-03",
      summary:
        "Broad Exception catch block in verify_external_jwks swallows token verification errors, masking authentication failure telemetry.",
      why_it_matters:
        "Catching base Exception without logging or differentiating error types suppresses expired key notices, network partition failures, and malformed signature alerts, masquerading attacks as simple missing tokens.",
      evidence_explanation:
        "Lines 36-39 wrap jwt.decode in try/except Exception and immediately return None without recording error context or telemetry.",
      architectural_impact:
        "Silenced error boundaries erode audit observability. Security monitoring systems cannot differentiate between a legitimate expired user session and an ongoing cryptographic spoofing attack.",
      remediation:
        "1. Catch PyJWTError specifically rather than generic Exception.\n2. Emit structured warning logs with correlation IDs.\n3. Return a typed result (e.g., Result[TokenClaims, AuthFailureReason]).",
      suggested_pattern: `# Explicit error handling with structured logging
import jwt
from jwt.exceptions import PyJWTError
import logging

logger = logging.getLogger(__name__)

def verify_external_jwks(token_str: str) -> dict | None:
    try:
        return jwt.decode(token_str, key=JWKS_CACHE, algorithms=["RS256"])
    except PyJWTError as exc:
        logger.warning("JWT verification rejected: %s", exc)
        return None`,
      confidence: "high",
      generated_at: "2026-10-31T10:05:00.000Z",
      model: "gemini-1.5-flash",
      prompt_version: "1",
      disclaimer:
        "AI-generated explanation — advisory only. Does not alter deterministic findings or scores.",
    },
  },
  {
    id: "pair-4",
    title: "Domain Coupling & Circular Import Cycle",
    rule_id: "ENT-ARCH-002",
    severity: "medium",
    category: "Architecture & Modularity",
    fileName: "src/domains/accounts/account_service.ts",
    fileLang: "typescript",
    lineStart: 8,
    lineEnd: 24,
    highlightLines: [10, 11, 12, 13],
    codeSnippet: `import { db } from "@/database";
// CYCLE: AccountService directly imports UserService which imports AccountService
import { UserService } from "@/domains/users/user_service";

export class AccountService {
  private userService = new UserService();

  async getAccountWithUser(accountId: string) {
    const acc = await db.accounts.findById(accountId);
    const user = await this.userService.getUser(acc.ownerId);
    return { ...acc, user };
  }
}`,
    explanation: {
      finding_id: "finding-demo-04",
      summary:
        "Circular dependency cycle detected between AccountService and UserService across domain boundaries.",
      why_it_matters:
        "Direct mutual imports prevent tree-shaking, cause undefined runtime evaluation order during startup, and tightly couple account operations with user operations in violation of clean domain boundaries.",
      evidence_explanation:
        "Lines 10-13 in account_service.ts import UserService, while user_service.ts imports AccountService, forming a closed topological loop.",
      architectural_impact:
        "Cyclic coupling makes unit testing difficult by requiring complex mock fixtures and impedes decomposing domains into independent packages or microservices.",
      remediation:
        "1. Introduce a domain event or shared interface in a shared/contracts directory.\n2. Use dependency inversion so both services depend on abstract ports.\n3. Defer circular resolution using event emitters or command handlers.",
      suggested_pattern: `// Invert dependency via shared ports
import type { UserLookupPort } from "@/shared/ports";

export class AccountService {
  constructor(private userLookup: UserLookupPort) {}
  
  async resolveAccountUser(accountId: string) {
    return this.userLookup.getUserForAccount(accountId);
  }
}`,
      confidence: "high",
      generated_at: "2026-10-31T10:05:00.000Z",
      model: "gemini-1.5-flash",
      prompt_version: "1",
      disclaimer:
        "AI-generated explanation — advisory only. Does not alter deterministic findings or scores.",
    },
  },
];

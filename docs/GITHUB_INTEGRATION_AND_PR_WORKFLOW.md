# Phase 12 — GitHub Integration & Pull Request Security/Debt Workflow

## Overview

The **GitHub Integration & Pull Request Security/Debt Workflow** connects Entropy's deterministic static analysis engine directly into developer CI/CD and Pull Request lifecycles. It enables repositories to compute real, deterministic architectural and security debt differentials between a PR's **Base SHA** and **Head SHA** without running arbitrary code.

### Core Architectural Principle

```
                 GitHub Repository
                         │
                    Pull Request (Base SHA vs Head SHA)
                         │
              GitHub Webhook / API Layer
            (HMAC X-Hub-Signature-256 Verified)
                         │
             Isolated Source Acquisition
            (git-archive / Hooks Disabled)
                         │
             Deterministic Scan Engine
          ├── Base Scan: Findings & Score
          └── Head Scan: Findings & Score
                         │
         Phase 10 Comparison Engine (Reused)
      ├── Score Delta (Head Score - Base Score)
      ├── New Debt Findings (Introduced)
      ├── Resolved Debt Findings (Remediated)
      └── Persistent Debt Findings (Unchanged)
                         │
             Persistent Storage (SQLite)
                         │
            ┌────────────┴────────────┐
            ▼                         ▼
    GitHub Check Run           Entropy Dashboard
  (Neutral / Informational)     (Interactive Diff)
```

---

## 1. Non-Negotiable Invariants

1. **Deterministic Static Analysis as Source of Truth**:
   The GitHub integration layer is strictly a transport and reporting mechanism. It never modifies findings, severities, confidences, categories, evidence, scores, or lifecycle classifications.
2. **Reuse of Phase 10 Comparison Engine**:
   Entropy reuses its existing `ComparisonService` to compute finding lifecycles (`NEW`, `RESOLVED`, `PERSISTENT`) and score movements, guaranteeing zero duplication of comparison logic.
3. **Zero Code Execution**:
   Entropy NEVER executes repository code, imports modules, runs npm/pip scripts, starts servers, or triggers repository git hooks. Repository contents are treated as untrusted data.
4. **Informational Reporting**:
   Check Runs and PR comments are strictly informational (`neutral` conclusion on success). Entropy does not arbitrarily block merges or enforce mandatory gates in Phase 12.
5. **AI Advisory Boundary**:
   AI explanations remain advisory and are never used to approve, reject, suppress findings, or determine PR security exploitability.

---

## 2. Webhook Security & Idempotency

### Cryptographic Signature Verification
All incoming webhooks must include an `X-Hub-Signature-256` header. The payload is verified using constant-time HMAC-SHA256 (`hmac.compare_digest`) against `settings.GITHUB_WEBHOOK_SECRET`. Unsigned or mismatched requests are rejected with `401 Unauthorized`.

### Idempotency Protection
Analyses are uniquely keyed by:
$$\text{Target} = (\text{owner}, \text{repo}, \text{pr\_number}, \text{base\_sha}, \text{head\_sha})$$

If duplicate webhooks arrive for an already completed target, the cached completed record is returned immediately without duplicate repository scans.

### Concurrency & Out-of-Order Commit Protection
If commit $A$ starts analysis, and commit $B$ starts shortly after, commit $B$ might finish before commit $A$. If commit $A$ finishes later, Entropy detects that $B$ has already superseded $A$, and marks commit $A$'s record with `is_current_head = False`, preventing stale commits from overwriting the latest PR status.

---

## 3. Isolated Source Acquisition

Repository states at exact commit SHAs are acquired via `backend/app/github/source.py`:
- **Strict SHA Validation**: Commit SHAs are validated with regex `^[0-9a-fA-F]{4,64}$` to prevent shell injection or directory traversal.
- **Git-Archive Export**: By default, `git archive --format=tar <commit_sha>` is used. This exports only tracked files, ignores `.git` hooks, and executes zero repo scripts.
- **Tar Extraction Safety**: Archive extraction verifies all member destinations to prevent directory traversal ("zip slip") and absolute symlink vulnerabilities.
- **Isolated Temporary Directories**: Checkouts occur inside `tempfile.mkdtemp` and are cleaned up via context managers (`temporary_checkout`).

---

## 4. GitHub Check Runs & PR Comments

### Check Run Payload
- **Status**: `in_progress` while scanning, `completed` when done.
- **Conclusion**: `neutral` (informational report that does not block PR merges).
- **Summary**: Objective debt metrics:
  - Base Score $\to$ Head Score (Score Delta)
  - New Debt count
  - Resolved Debt count
  - Persistent Debt count
  - Affected debt categories
  - Deep link to the Entropy Dashboard comparison view.

### PR Comments
- Updates an existing Entropy comment (identified by `<!-- entropy-pr-report -->`) rather than creating a new comment on every push, preventing PR thread notification noise.

---

## 5. Minimum GitHub App Permissions

To install and operate Entropy as a GitHub App:

| Permission | Access | Purpose |
| :--- | :--- | :--- |
| **Pull Requests** | Read & Write | Read PR metadata (base/head SHAs) and post markdown summary comments. |
| **Checks** | Read & Write | Create and update informational Check Runs. |
| **Contents** | Read-only | Fetch commit metadata and archive snapshots. |
| **Webhooks** | `pull_request` | Receive `opened`, `synchronize`, and `reopened` events. |

---

## 6. REST API Reference

### Webhooks
- `POST /api/v1/webhooks/github`
  - Validates `X-Hub-Signature-256` HMAC.
  - Processes `pull_request` events and triggers background analysis.

### Pull Requests
- `POST /api/v1/github/prs/{owner}/{repo}/{pr_number}/analyze`
  - Manually triggers Base vs Head comparison for a PR.
- `GET /api/v1/github/prs/{owner}/{repo}/{pr_number}`
  - Returns the latest/active `PRAnalysisRecord`.
- `GET /api/v1/github/prs/{owner}/{repo}/{pr_number}/comparison`
  - Returns the full verbatim `ScanComparisonResult` for the PR.
- `GET /api/v1/github/prs/{owner}/{repo}`
  - Lists recent PR analysis records for the repository.

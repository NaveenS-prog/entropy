# Developer Workflow Guide

This guide describes how engineers and teams adopt Entropy locally and incorporate it into day-to-day development.

---

## 1. Quickstart: Onboarding a New or Existing Repository

### Step 1: Initialize Configuration
Initialize `.entropy.yml` at the repository root:
```bash
entropy init
```
This generates a starter `.entropy.yml` with default languages and recommended exclude patterns.

### Step 2: Validate Configuration
Ensure the configuration file is structurally and semantically valid:
```bash
entropy config validate
```

### Step 3: Establish a Baseline
If onboarding an existing codebase with preexisting findings, capture the current state as a baseline:
```bash
entropy baseline create
```
This creates `.entropy-baseline.json` containing only finding metadata and fingerprints.

### Step 4: Run Daily Checks
During everyday feature development and before opening pull requests:
```bash
entropy check
```
Entropy scans the repository, compares changes against `.entropy-baseline.json`, evaluates policy rules against the delta, and outputs actionable feedback.

---

## 2. Inspecting Findings

Inspect all current findings:
```bash
entropy findings
```

Filter only new findings introduced since the baseline:
```bash
entropy findings --new
```

Review suppressed findings and their audit justifications:
```bash
entropy findings --suppressed
```

---

## 3. Exit Codes Reference

| Exit Code | Meaning | Description |
|-----------|---------|-------------|
| `0` | PASS | Policy passed and no blocking criteria violated. |
| `1` | POLICY_FAIL | One or more policy rules failed (e.g. new critical debt findings or score degradation). |
| `2` | CONFIG_ERROR | Configuration validation failed (e.g. invalid YAML, path traversal, unknown rule ID). |
| `3` | SYSTEM_ERROR | System-level or unexpected runtime error (e.g. unreadable path, disk full). |

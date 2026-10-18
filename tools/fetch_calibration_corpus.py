#!/usr/bin/env python3
"""Fetch and build pinned calibration corpus from real, independently authored open-source projects.

Downloads the smallest relevant subdirectories/files for known-vulnerable and known-clean
projects (Python, JavaScript, TypeScript) and generates manifest.json with pinned commit SHAs
and licenses.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import urllib.request

ROOT_DIR = Path(__file__).resolve().parent.parent
CORPUS_DIR = ROOT_DIR / "backend" / "tests" / "calibration" / "corpus"

PROJECTS = [
    # --- Tuning Set: Clean Projects ---
    {
        "name": "express-auth-clean",
        "type": "clean",
        "set": "tuning",
        "language": "javascript",
        "repo": "expressjs/express",
        "ref": "master",
        "license": "MIT",
        "description": "Official Express authentication example with bcrypt hashing and session middleware.",
        "files": {
            "examples/auth/index.js": "index.js",
        },
    },
    {
        "name": "fastapi-security-clean",
        "type": "clean",
        "set": "tuning",
        "language": "python",
        "repo": "fastapi/fastapi",
        "ref": "master",
        "license": "MIT",
        "description": "Official FastAPI OAuth2 security tutorial module with JWT validation, password hashing, and dependency injection.",
        "files": {
            "docs_src/security/tutorial002_py310.py": "security.py",
        },
    },
    # --- Tuning Set: Vulnerable Projects ---
    {
        "name": "vulnerable-flask",
        "type": "vulnerable",
        "set": "tuning",
        "language": "python",
        "repo": "we45/Vulnerable-Flask-App",
        "ref": "master",
        "license": "MIT",
        "description": "Deliberately vulnerable Flask app exhibiting SQL injection, unauthenticated routes, and command execution.",
        "files": {
            "app/app.py": "app.py",
        },
    },
    {
        "name": "dvna-vulnerable",
        "type": "vulnerable",
        "set": "tuning",
        "language": "javascript",
        "repo": "appsecco/dvna",
        "ref": "master",
        "license": "MIT",
        "description": "Damn Vulnerable NodeJS Application routes and handlers with SQL injection and missing route authorization.",
        "files": {
            "routes/app.js": "app.js",
            "routes/main.js": "main.js",
            "core/appHandler.js": "appHandler.js",
        },
    },
    # --- Held-Out Set: Clean Projects ---
    {
        "name": "fastapi-clean-oauth2",
        "type": "clean",
        "set": "held_out",
        "language": "python",
        "repo": "fastapi/fastapi",
        "ref": "master",
        "license": "MIT",
        "description": "Official FastAPI password flow tutorial module with OAuth2PasswordBearer and User dependency injection.",
        "files": {
            "docs_src/security/tutorial001_py310.py": "tutorial.py",
        },
    },
    {
        "name": "nestjs-auth-clean",
        "type": "clean",
        "set": "held_out",
        "language": "typescript",
        "repo": "nestjs/nest",
        "ref": "master",
        "license": "MIT",
        "description": "Official NestJS authentication JWT controller with @Public() decorator and guard enforcement.",
        "files": {
            "sample/19-auth-jwt/src/auth/auth.controller.ts": "auth.controller.ts",
        },
    },
    # --- Held-Out Set: Vulnerable Projects ---
    {
        "name": "hackable-flask-vulnerable",
        "type": "vulnerable",
        "set": "held_out",
        "language": "python",
        "repo": "JasonHinds13/hackable",
        "ref": "master",
        "license": "MIT",
        "description": "Deliberately vulnerable Flask web API with raw SQL query concatenation and missing authentication.",
        "files": {
            "main.py": "main.py",
        },
    },
    {
        "name": "juice-shop-vulnerable",
        "type": "vulnerable",
        "set": "held_out",
        "language": "typescript",
        "repo": "juice-shop/juice-shop",
        "ref": "master",
        "license": "MIT",
        "description": "OWASP Juice Shop server routes with unauthenticated administrative endpoints and privileged state mutation.",
        "files": {
            "server.ts": "server.ts",
        },
    },
]


def fetch_corpus() -> None:
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    manifest_entries = []

    for proj in PROJECTS:
        p_name = proj["name"]
        repo = proj["repo"]
        ref = proj["ref"]
        target_dir = CORPUS_DIR / p_name
        target_dir.mkdir(parents=True, exist_ok=True)

        print(f"Fetching {p_name} ({repo} @ {ref})...")

        # Resolve commit SHA
        api_url = f"https://api.github.com/repos/{repo}/commits/{ref}"
        req = urllib.request.Request(api_url, headers={"User-Agent": "Entropy-Calibration-Fetcher"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                commit_data = json.loads(resp.read().decode("utf-8"))
                commit_sha = commit_data["sha"]
        except Exception as err:
            print(f"  Warning: could not resolve commit SHA via API ({err}), falling back to ref: {ref}")
            commit_sha = ref

        saved_files = []
        for remote_path, local_name in proj["files"].items():
            raw_url = f"https://raw.githubusercontent.com/{repo}/{commit_sha}/{remote_path}"
            r_req = urllib.request.Request(raw_url, headers={"User-Agent": "Entropy-Calibration-Fetcher"})
            try:
                with urllib.request.urlopen(r_req, timeout=15) as r_resp:
                    content = r_resp.read()
                    dest_file = target_dir / local_name
                    dest_file.write_bytes(content)
                    saved_files.append(local_name)
                    print(f"  Downloaded {local_name} ({len(content)} bytes)")
            except Exception as err:
                print(f"  Failed to download {remote_path}: {err}", file=sys.stderr)
                raise

        manifest_entries.append({
            "name": p_name,
            "type": proj["type"],
            "set": proj["set"],
            "language": proj["language"],
            "repo": repo,
            "commit_sha": commit_sha,
            "license": proj["license"],
            "description": proj["description"],
            "relative_dir": p_name,
            "files": saved_files,
        })

    manifest_path = CORPUS_DIR / "manifest.json"
    manifest_data = {
        "description": "Real, independently authored calibration and held-out corpus for Entropy scoring validation.",
        "projects": manifest_entries,
    }
    manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
    print(f"\nCorpus successfully built at {CORPUS_DIR}")
    print(f"Manifest written to {manifest_path} ({len(manifest_entries)} projects)")


if __name__ == "__main__":
    fetch_corpus()

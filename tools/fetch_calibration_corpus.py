#!/usr/bin/env python3
"""Fetch and build pinned calibration corpus from real, independently authored open-source projects.

Downloads the smallest relevant subdirectories/files for known-vulnerable and known-clean
projects (Python, JavaScript, TypeScript) using the pinned commit SHAs recorded in manifest.json
(never master or branch heads). Refuses to continue if any download fails, computes SHA256
checksums for every file, and records them in manifest.json.
"""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
CORPUS_DIR = ROOT_DIR / "backend" / "tests" / "calibration" / "corpus"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"

# Remote path mappings for corpus files: project_name -> {remote_path: local_name}
PROJECT_REMOTE_FILES: dict[str, dict[str, str]] = {
    "express-auth-clean": {
        "examples/auth/index.js": "index.js",
    },
    "fastapi-security-clean": {
        "docs_src/security/tutorial002_py310.py": "security.py",
    },
    "vulnerable-flask": {
        "app/app.py": "app.py",
    },
    "dvna-vulnerable": {
        "routes/app.js": "app.js",
        "routes/main.js": "main.js",
        "core/appHandler.js": "appHandler.js",
    },
    "fastapi-clean-oauth2": {
        "docs_src/security/tutorial001_py310.py": "tutorial.py",
    },
    "nestjs-auth-clean": {
        "sample/19-auth-jwt/src/auth/auth.controller.ts": "auth.controller.ts",
    },
    "hackable-flask-vulnerable": {
        "main.py": "main.py",
    },
    "juice-shop-vulnerable": {
        "server.ts": "server.ts",
    },
}


def fetch_corpus() -> None:
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(f"Manifest file not found at {MANIFEST_PATH}. Cannot resolve pinned commit SHAs.")

    manifest_data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    projects = manifest_data.get("projects", [])
    if not projects:
        raise ValueError("No projects defined in manifest.json")

    # Verify no upstream repo SHA is reused between tuning and held-out sets
    tuning_shas: dict[str, str] = {}
    held_out_shas: dict[str, str] = {}
    for p in projects:
        name = p["name"]
        sha = p.get("commit_sha", "").strip()
        pset = p.get("set", "")
        if not sha or sha.lower() in ("master", "main", "head"):
            raise ValueError(
                f"Project '{name}' must have a pinned commit SHA in manifest.json (got: '{sha}'). Refusing 'master'."
            )
        if pset == "tuning":
            tuning_shas[name] = sha
        elif pset == "held_out":
            held_out_shas[name] = sha

    for t_name, t_sha in tuning_shas.items():
        for h_name, h_sha in held_out_shas.items():
            if t_sha == h_sha:
                raise ValueError(
                    f"Corpus integrity violation: tuning project '{t_name}' and held-out project '{h_name}' "
                    f"share the same commit SHA: {t_sha}"
                )

    CORPUS_DIR.mkdir(parents=True, exist_ok=True)

    for proj in projects:
        p_name = proj["name"]
        repo = proj["repo"]
        commit_sha = proj["commit_sha"].strip()
        target_dir = CORPUS_DIR / proj.get("relative_dir", p_name)
        target_dir.mkdir(parents=True, exist_ok=True)

        remote_mapping = PROJECT_REMOTE_FILES.get(p_name)
        if not remote_mapping:
            raise ValueError(f"No remote file mapping configured for project '{p_name}'")

        print(f"Fetching {p_name} ({repo} @ {commit_sha})...")

        saved_files: list[str] = []
        sha256_map: dict[str, str] = {}

        for remote_path, local_name in remote_mapping.items():
            raw_url = f"https://raw.githubusercontent.com/{repo}/{commit_sha}/{remote_path}"
            req = urllib.request.Request(raw_url, headers={"User-Agent": "Entropy-Calibration-Fetcher/1.0"})
            try:
                with urllib.request.urlopen(req, timeout=20) as resp:
                    if resp.status != 200:
                        raise RuntimeError(f"HTTP {resp.status} received from {raw_url}")
                    content = resp.read()
                    if not content:
                        raise RuntimeError(f"Received empty response from {raw_url}")
            except Exception as err:
                print(f"FATAL: Failed to download {remote_path} from {raw_url}: {err}", file=sys.stderr)
                # Refuse to continue if a download fails
                raise RuntimeError(f"Corpus fetch aborted: failed to download {remote_path}: {err}") from err

            file_hash = hashlib.sha256(content).hexdigest()
            dest_file = target_dir / local_name
            dest_file.write_bytes(content)
            saved_files.append(local_name)
            sha256_map[local_name] = file_hash
            print(f"  Downloaded {local_name} ({len(content)} bytes, sha256: {file_hash[:12]}...)")

        proj["files"] = saved_files
        proj["sha256"] = sha256_map
        proj["file_hashes"] = sha256_map

    MANIFEST_PATH.write_text(json.dumps(manifest_data, indent=2) + "\n", encoding="utf-8")
    print(f"\nCorpus successfully built and verified at {CORPUS_DIR}")
    print(f"Manifest updated at {MANIFEST_PATH} ({len(projects)} projects)")


if __name__ == "__main__":
    fetch_corpus()

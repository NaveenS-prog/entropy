"""Regression test verifying integrity and SHA-256 digests of the calibration corpus.

Ensures:
1. Every corpus file matches the exact SHA-256 hash recorded in manifest.json.
2. All commit SHAs are pinned and never 'master', 'main', or floating references.
3. No upstream commit SHA is reused between tuning and held-out evaluation sets.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

CORPUS_DIR = Path(__file__).parent / "corpus"
MANIFEST_FILE = CORPUS_DIR / "manifest.json"


@pytest.fixture(scope="module")
def manifest_data():
    assert MANIFEST_FILE.exists(), f"manifest.json missing at {MANIFEST_FILE}"
    return json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))


def test_corpus_manifest_structure_and_no_floating_refs(manifest_data):
    projects = manifest_data.get("projects", [])
    assert len(projects) >= 8, "Expected at least 8 projects in calibration corpus manifest"

    tuning_shas: dict[str, str] = {}
    held_out_shas: dict[str, str] = {}

    for p in projects:
        name = p["name"]
        commit_sha = p.get("commit_sha", "").strip()
        pset = p.get("set", "")

        assert commit_sha, f"Project {name} missing commit_sha"
        assert commit_sha.lower() not in ("master", "main", "head"), (
            f"Project {name} has floating ref '{commit_sha}'; must be pinned commit SHA"
        )
        assert len(commit_sha) >= 7, f"Project {name} commit SHA '{commit_sha}' is suspiciously short"

        if pset == "tuning":
            tuning_shas[name] = commit_sha
        elif pset == "held_out":
            held_out_shas[name] = commit_sha

    # Verify no upstream repo SHA is reused between tuning and held-out sets
    for t_name, t_sha in tuning_shas.items():
        for h_name, h_sha in held_out_shas.items():
            assert t_sha != h_sha, (
                f"Data leakage: tuning project '{t_name}' and held-out project '{h_name}' "
                f"share the same upstream commit SHA ({t_sha})"
            )


def test_corpus_files_sha256_integrity(manifest_data):
    projects = manifest_data.get("projects", [])
    verified_files_count = 0

    for p in projects:
        p_name = p["name"]
        rel_dir = p.get("relative_dir", p_name)
        project_dir = CORPUS_DIR / rel_dir
        assert project_dir.exists(), f"Project directory {project_dir} does not exist"

        files = p.get("files", [])
        assert len(files) > 0, f"Project {p_name} has no files listed in manifest"

        sha256_map = p.get("sha256") or p.get("file_hashes")
        assert sha256_map, f"Project {p_name} missing sha256 checksums in manifest"

        for file_name in files:
            file_path = project_dir / file_name
            assert file_path.exists(), f"Corpus file {file_path} missing on disk"

            actual_sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
            expected_sha256 = sha256_map.get(file_name)

            assert expected_sha256 is not None, f"Missing expected sha256 for {file_name} in manifest"
            assert actual_sha256 == expected_sha256, (
                f"Corpus file integrity violation for {p_name}/{file_name}: "
                f"actual={actual_sha256} != expected={expected_sha256}"
            )
            verified_files_count += 1

    assert verified_files_count >= 10, f"Expected at least 10 corpus files verified, got {verified_files_count}"

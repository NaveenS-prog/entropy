"""Unit tests for repository file discovery, security safeguards, and language classification."""

from pathlib import Path

import pytest

from app.core.errors import (
    RepositoryLimitExceededError,
    RepositoryNotADirectoryError,
    RepositoryNotFoundError,
)
from app.models.domain.enums import SupportedLanguage
from app.repository.config import ScannerConfig
from app.repository.discoverer import RepositoryDiscoverer
from app.repository.sources import LocalRepositorySource

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def test_discover_clean_python_project():
    project_dir = FIXTURES_DIR / "clean_python_project"
    discoverer = RepositoryDiscoverer()
    result = discoverer.discover_repository(project_dir)

    assert result.total_files_inspected == 3
    assert len(result.source_files) == 3
    assert len(result.skipped_files) == 0

    rel_paths = [f.relative_path for f in result.source_files]
    assert "main.py" in rel_paths
    assert "models/user.py" in rel_paths
    assert "utils/helpers.py" in rel_paths

    for sf in result.source_files:
        assert sf.language == SupportedLanguage.PYTHON
        assert sf.analysis_supported is True
        assert sf.skip_reason is None
        assert sf.line_count > 0
        assert sf.size_bytes > 0


def test_discover_mixed_language_project():
    project_dir = FIXTURES_DIR / "mixed_language_project"
    discoverer = RepositoryDiscoverer()
    result = discoverer.discover_repository(project_dir)

    languages_detected = {f.language for f in result.source_files}
    assert SupportedLanguage.PYTHON in languages_detected
    assert SupportedLanguage.JAVASCRIPT in languages_detected
    assert SupportedLanguage.TYPESCRIPT in languages_detected
    assert SupportedLanguage.JAVA in languages_detected
    assert SupportedLanguage.C in languages_detected
    assert SupportedLanguage.CPP in languages_detected
    assert SupportedLanguage.GO in languages_detected
    assert SupportedLanguage.RUST in languages_detected


def test_unsupported_language_marking():
    project_dir = FIXTURES_DIR / "mixed_language_project"
    discoverer = RepositoryDiscoverer()
    result = discoverer.discover_repository(project_dir)

    for sf in result.source_files:
        if sf.language == SupportedLanguage.PYTHON:
            assert sf.analysis_supported is True
            assert sf.skip_reason is None
        else:
            assert sf.analysis_supported is False
            assert sf.skip_reason == "language_detected_but_analyzer_unavailable"


def test_ignored_directories_and_patterns():
    project_dir = FIXTURES_DIR / "ignored_directories_project"
    discoverer = RepositoryDiscoverer()
    result = discoverer.discover_repository(project_dir)

    # Only src/valid.py should be discovered as valid source file
    rel_paths = [f.relative_path for f in result.source_files]
    assert "src/valid.py" in rel_paths

    # Excluded directories must not leak into discovered files
    for path in rel_paths:
        assert not path.startswith("node_modules/")
        assert not path.startswith(".git/")
        assert not path.startswith("venv/")
        assert not path.startswith("__pycache__/")
        assert not path.startswith("dist/")
        assert not path.startswith("build/")
        assert not path.startswith(".next/")
        assert not path.startswith("target/")
        assert not path.startswith("vendor/")
        assert not path.startswith("ignored_custom/")
        assert not path.endswith(".ignored.py")

    assert result.ignored_files_count > 0


def test_large_file_handling():
    project_dir = FIXTURES_DIR / "large_file_project"
    # Set limit to 1MB so enormous.py (2.5MB) is skipped safely
    config = ScannerConfig(max_file_size_bytes=1024 * 1024)
    discoverer = RepositoryDiscoverer(config=config)
    result = discoverer.discover_repository(project_dir)

    discovered_names = [f.relative_path for f in result.source_files]
    assert "normal.py" in discovered_names
    assert "enormous.py" not in discovered_names

    skipped_reasons = {sf.path: sf.reason for sf in result.skipped_files}
    assert "enormous.py" in skipped_reasons
    assert skipped_reasons["enormous.py"] == "file_size_exceeds_limit"


def test_binary_and_corrupt_files():
    project_dir = FIXTURES_DIR / "invalid_files_project"
    discoverer = RepositoryDiscoverer()
    result = discoverer.discover_repository(project_dir)

    discovered_names = [f.relative_path for f in result.source_files]
    assert "valid.py" in discovered_names
    assert "image.png" not in discovered_names
    assert "corrupt.py" not in discovered_names
    assert "bad_encoding.py" not in discovered_names

    skipped_reasons = {sf.path: sf.reason for sf in result.skipped_files}
    assert skipped_reasons["image.png"] == "binary_file"
    assert skipped_reasons["corrupt.py"] == "binary_content_detected"
    assert skipped_reasons["bad_encoding.py"] == "unsupported_encoding_or_unreadable"


def test_invalid_repository_path():
    discoverer = RepositoryDiscoverer()
    with pytest.raises(RepositoryNotFoundError):
        discoverer.discover_repository("/path/does/not/exist/at/all")


def test_path_is_file_not_directory(tmp_path):
    temp_file = tmp_path / "file.py"
    temp_file.write_text("x = 1\n")
    source = LocalRepositorySource(temp_file)
    with pytest.raises(RepositoryNotADirectoryError):
        source.validate()


def test_file_count_limit_exceeded(tmp_path):
    # Create 5 files with limit of 3
    for i in range(5):
        (tmp_path / f"file_{i}.py").write_text("x = 1\n")

    config = ScannerConfig(max_file_count=3)
    discoverer = RepositoryDiscoverer(config=config)
    with pytest.raises(RepositoryLimitExceededError):
        discoverer.discover_repository(tmp_path)


def test_repo_size_limit_exceeded(tmp_path):
    (tmp_path / "big.py").write_text("x" * 2000)
    config = ScannerConfig(max_repo_size_bytes=1000)
    discoverer = RepositoryDiscoverer(config=config)
    with pytest.raises(RepositoryLimitExceededError):
        discoverer.discover_repository(tmp_path)


def test_symlink_security(tmp_path):
    # Symlink pointing outside the repo
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    secret_file = outside_dir / "secret.py"
    secret_file.write_text("SECRET = 123\n")

    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    symlink_file = repo_dir / "link_to_outside.py"
    symlink_file.symlink_to(secret_file)

    # 1. By default follow_symlinks=False -> skipped
    discoverer = RepositoryDiscoverer(ScannerConfig(follow_symlinks=False))
    result = discoverer.discover_repository(repo_dir)
    assert len(result.source_files) == 0
    assert any(sf.reason == "symlink_ignored" for sf in result.skipped_files)

    # 2. Even if follow_symlinks=True, breakout is blocked
    discoverer_follow = RepositoryDiscoverer(ScannerConfig(follow_symlinks=True))
    result_follow = discoverer_follow.discover_repository(repo_dir)
    assert len(result_follow.source_files) == 0
    assert any(
        sf.reason == "symlink_points_outside_repository" for sf in result_follow.skipped_files
    )

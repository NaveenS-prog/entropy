"""Unit tests for RepositoryManifest generation and directory structure building."""

from pathlib import Path

from app.models.domain.enums import SupportedLanguage
from app.repository.discoverer import RepositoryDiscoverer
from app.repository.manifest import ManifestBuilder

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def test_manifest_generation_structure():
    project_dir = FIXTURES_DIR / "clean_python_project"
    discoverer = RepositoryDiscoverer()
    discovery = discoverer.discover_repository(project_dir)

    manifest = ManifestBuilder.build("clean-python", project_dir, discovery)

    assert manifest.repository.name == "clean-python"
    assert manifest.repository.source_files == 3
    assert manifest.repository.total_files == 3
    assert manifest.repository.total_source_loc > 0
    assert manifest.repository.total_source_size > 0
    assert manifest.languages.get("python") == 3

    assert len(manifest.files) == 3
    for f in manifest.files:
        assert f.language == "python"
        assert f.analysis_supported is True
        assert f.line_count > 0

    assert manifest.directory_structure is not None
    assert manifest.directory_structure.name == "clean-python"
    assert manifest.directory_structure.type == "directory"


def test_manifest_directory_tree_nesting():
    project_dir = FIXTURES_DIR / "clean_python_project"
    discoverer = RepositoryDiscoverer()
    discovery = discoverer.discover_repository(project_dir)

    manifest = ManifestBuilder.build("clean-python", project_dir, discovery)
    tree = manifest.directory_structure
    assert tree is not None

    child_names = [c.name for c in tree.children]
    assert "models" in child_names
    assert "utils" in child_names
    assert "main.py" in child_names

    models_node = next(c for c in tree.children if c.name == "models")
    assert models_node.type == "directory"
    models_files = [c.name for c in models_node.children]
    assert "user.py" in models_files


def test_manifest_mixed_language_statistics():
    project_dir = FIXTURES_DIR / "mixed_language_project"
    discoverer = RepositoryDiscoverer()
    discovery = discoverer.discover_repository(project_dir)

    manifest = ManifestBuilder.build("mixed-lang", project_dir, discovery)

    # All recognized languages should appear in manifest.languages
    expected_langs = {
        SupportedLanguage.PYTHON.value,
        SupportedLanguage.JAVASCRIPT.value,
        SupportedLanguage.TYPESCRIPT.value,
        SupportedLanguage.JAVA.value,
        SupportedLanguage.C.value,
        SupportedLanguage.CPP.value,
        SupportedLanguage.GO.value,
        SupportedLanguage.RUST.value,
    }
    for lang in expected_langs:
        assert lang in manifest.languages
        assert manifest.languages[lang] >= 1

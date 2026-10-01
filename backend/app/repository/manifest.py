"""Manifest builder constructing structured RepositoryManifest artifacts."""

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from app.models.domain.manifest import (
    DirectoryNode,
    RepositoryManifest,
    RepositoryManifestSummary,
    SkippedFileRecord,
    SourceFileMetadata,
)
from app.repository.discoverer import DiscoveryResult


class ManifestBuilder:
    """Constructs a deterministic, complete RepositoryManifest from discovery results."""

    @staticmethod
    def build(
        repo_name: str,
        root_path: Path,
        discovery: DiscoveryResult,
        timestamp: datetime | None = None,
    ) -> RepositoryManifest:
        """Assemble all discovered files, language stats, and directory hierarchy into a manifest."""
        scan_time = timestamp or datetime.now(UTC)

        # 1. Compute language statistics
        lang_counter = Counter(f.language.value for f in discovery.source_files)
        # Sort by count descending, then alphabetically
        languages = dict(sorted(lang_counter.items(), key=lambda item: (-item[1], item[0])))

        # 2. Convert discovered files into SourceFileMetadata
        source_file_metas = [
            SourceFileMetadata(
                path=f.relative_path,
                language=f.language.value,
                size=f.size_bytes,
                line_count=f.line_count,
                analysis_supported=f.analysis_supported,
                skip_reason=f.skip_reason,
            )
            for f in discovery.source_files
        ]

        # 3. Assemble repository summary
        summary = RepositoryManifestSummary(
            name=repo_name,
            path=str(root_path.resolve()),
            scan_timestamp=scan_time,
            total_files=discovery.total_files_inspected,
            source_files=len(discovery.source_files),
            ignored_files=discovery.ignored_files_count,
            skipped_files=len(discovery.skipped_files),
            total_source_size=discovery.total_source_bytes,
            total_source_loc=discovery.total_source_loc,
        )

        # 4. Build hierarchical directory structure
        dir_tree = ManifestBuilder._build_directory_tree(
            root_name=repo_name,
            source_files=discovery.source_files,
            skipped_files=discovery.skipped_files,
        )

        return RepositoryManifest(
            repository=summary,
            languages=languages,
            files=source_file_metas,
            skipped_files=discovery.skipped_files,
            directory_structure=dir_tree,
        )

    @staticmethod
    def _build_directory_tree(
        root_name: str,
        source_files: list,
        skipped_files: list[SkippedFileRecord],
    ) -> DirectoryNode:
        """Create a nested tree of DirectoryNodes for the repository files."""
        root_node = DirectoryNode(
            name=root_name,
            path="",
            type="directory",
            size=0,
            children=[],
        )

        # Helper mapping of directory path to node
        dir_map: dict[str, DirectoryNode] = {"": root_node}

        def get_or_create_dir(dir_path: str) -> DirectoryNode:
            if dir_path in dir_map:
                return dir_map[dir_path]

            parts = dir_path.split("/")
            parent_path = "/".join(parts[:-1]) if len(parts) > 1 else ""
            parent_node = get_or_create_dir(parent_path)

            node = DirectoryNode(
                name=parts[-1],
                path=dir_path,
                type="directory",
                size=0,
                children=[],
            )
            parent_node.children.append(node)
            dir_map[dir_path] = node
            return node

        # Add source files to directory tree
        for sf in source_files:
            rel = sf.relative_path
            parts = rel.split("/")
            if len(parts) > 1:
                parent_dir = "/".join(parts[:-1])
                parent_node = get_or_create_dir(parent_dir)
            else:
                parent_node = root_node

            parent_node.children.append(
                DirectoryNode(
                    name=parts[-1],
                    path=rel,
                    type="file",
                    size=sf.size_bytes,
                    children=[],
                )
            )

        # Recursively sort children: directories first, then files alphabetically
        def sort_children(node: DirectoryNode):
            node.children.sort(key=lambda c: (0 if c.type == "directory" else 1, c.name.lower()))
            for c in node.children:
                if c.type == "directory":
                    sort_children(c)

        sort_children(root_node)
        return root_node

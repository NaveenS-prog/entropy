"""Domain models for Repository Manifest generated during ingestion."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.models.domain.enums import SupportedLanguage


class SourceFileMetadata(BaseModel):
    """Metadata describing a recognized source file."""

    path: str = Field(..., description="Relative path from repository root")
    language: SupportedLanguage | str = Field(..., description="Detected programming language")
    size: int = Field(..., ge=0, description="File size in bytes")
    line_count: int | None = Field(default=None, ge=0, description="Total lines of code if text")
    analysis_supported: bool = Field(..., description="Whether static analysis is currently supported")
    skip_reason: str | None = Field(default=None, description="Reason analysis is skipped if not supported")


class SkippedFileRecord(BaseModel):
    """Record of a file that was skipped during scanning."""

    path: str = Field(..., description="Relative path from repository root")
    size: int = Field(..., ge=0, description="File size in bytes")
    reason: str = Field(..., description="Reason file was skipped (e.g. file_size_exceeds_limit, binary_file)")


class DirectoryNode(BaseModel):
    """Hierarchical node representing a directory or file in the repository tree."""

    name: str = Field(..., description="Directory or file name")
    path: str = Field(..., description="Relative path from repository root")
    type: Literal["directory", "file"] = Field(..., description="Node type")
    size: int = Field(default=0, ge=0, description="Size in bytes")
    children: list["DirectoryNode"] = Field(default_factory=list, description="Child nodes if directory")


class RepositoryManifestSummary(BaseModel):
    """High-level repository statistics for manifest."""

    name: str = Field(..., description="Repository name")
    path: str = Field(..., description="Resolved root path of the repository")
    scan_timestamp: datetime = Field(..., description="Timestamp when the scan took place")
    total_files: int = Field(default=0, ge=0, description="Total number of files inspected")
    source_files: int = Field(default=0, ge=0, description="Count of recognized source files")
    ignored_files: int = Field(default=0, ge=0, description="Count of files excluded by ignore rules or .gitignore")
    skipped_files: int = Field(default=0, ge=0, description="Count of files skipped due to limits/binary/errors")
    total_source_size: int = Field(default=0, ge=0, description="Total size of source files in bytes")
    total_source_loc: int = Field(default=0, ge=0, description="Total lines of code across source files")


class RepositoryManifest(BaseModel):
    """Complete structured manifest for an ingested repository."""

    repository: RepositoryManifestSummary = Field(..., description="Repository summary metadata")
    languages: dict[str, int] = Field(default_factory=dict, description="File counts per programming language")
    files: list[SourceFileMetadata] = Field(default_factory=list, description="All discovered source files")
    skipped_files: list[SkippedFileRecord] = Field(default_factory=list, description="Files skipped during scan")
    directory_structure: DirectoryNode | None = Field(default=None, description="Repository directory tree")

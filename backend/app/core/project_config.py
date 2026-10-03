"""Project configuration models and deterministic serialization for Entropy (.entropy.yml)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class ProjectMetaConfig(BaseModel):
    """Metadata describing the project."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, description="Unique project name")
    id: str | None = Field(default=None, description="Optional explicit project identifier")


class AnalysisConfig(BaseModel):
    """Repository analysis boundaries and filters."""

    model_config = ConfigDict(extra="forbid")

    languages: list[str] = Field(
        default_factory=lambda: ["python", "javascript", "typescript"],
        description="Target programming languages for static analysis",
    )
    exclude: list[str] = Field(
        default_factory=list,
        description="Directories or file glob patterns excluded from discovery",
    )

    @field_validator("languages")
    @classmethod
    def validate_languages(cls, v: list[str]) -> list[str]:
        valid = {"python", "javascript", "typescript"}
        for lang in v:
            if lang.lower() not in valid:
                raise ValueError(
                    f"Unsupported analysis language: '{lang}'. Supported: {sorted(valid)}"
                )
        return [lang.lower() for lang in v]

    @field_validator("exclude")
    @classmethod
    def validate_exclude_patterns(cls, v: list[str]) -> list[str]:
        for pattern in v:
            clean = pattern.strip()
            if ".." in clean.split("/"):
                raise ValueError(
                    f"Path traversal ('..') is strictly forbidden in exclude pattern: '{pattern}'"
                )
        return v


class ScoringConfig(BaseModel):
    """Configuration for scoring and baselining."""

    model_config = ConfigDict(extra="forbid")

    baseline: str = Field(
        default="auto",
        description="Baseline comparison mode: 'auto', 'strict', or 'off'",
    )
    baseline_file: str = Field(
        default=".entropy-baseline.json",
        description="Relative path to baseline JSON file",
    )

    @field_validator("baseline")
    @classmethod
    def validate_baseline_mode(cls, v: str) -> str:
        valid = {"auto", "strict", "off"}
        if v.lower() not in valid:
            raise ValueError(f"Invalid baseline mode: '{v}'. Supported: {sorted(valid)}")
        return v.lower()

    @field_validator("baseline_file")
    @classmethod
    def validate_baseline_file(cls, v: str) -> str:
        clean = v.strip()
        if ".." in clean.split("/"):
            raise ValueError(
                f"Path traversal ('..') is strictly forbidden in baseline_file path: '{v}'"
            )
        return clean


class PolicyRefConfig(BaseModel):
    """Reference to policy configuration file."""

    model_config = ConfigDict(extra="forbid")

    file: str | None = Field(
        default=None,
        description="Relative path to custom policy YAML/JSON file",
    )

    @field_validator("file")
    @classmethod
    def validate_policy_file(cls, v: str | None) -> str | None:
        if v is not None:
            clean = v.strip()
            if ".." in clean.split("/"):
                raise ValueError(
                    f"Path traversal ('..') is strictly forbidden in policy file path: '{v}'"
                )
            return clean
        return None


class OutputConfig(BaseModel):
    """Default output preferences."""

    model_config = ConfigDict(extra="forbid")

    format: str = Field(
        default="text",
        description="Default report format: 'text', 'json', or 'sarif'",
    )

    @field_validator("format")
    @classmethod
    def validate_format(cls, v: str) -> str:
        valid = {"text", "json", "sarif"}
        if v.lower() not in valid:
            raise ValueError(f"Invalid output format: '{v}'. Supported: {sorted(valid)}")
        return v.lower()


class IgnoreConfig(BaseModel):
    """Rule and finding suppression specifications."""

    model_config = ConfigDict(extra="forbid")

    rules: list[str] = Field(
        default_factory=list,
        description="List of rule IDs to suppress globally across project",
    )
    findings: list[str] = Field(
        default_factory=list,
        description="List of deterministic finding IDs or fingerprints to suppress",
    )


class EntropyProjectConfig(BaseModel):
    """Top-level strict schema for .entropy.yml project configuration."""

    model_config = ConfigDict(extra="forbid")

    version: int = Field(default=1, description="Configuration schema version")
    project: ProjectMetaConfig = Field(..., description="Project identity")
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    policy: PolicyRefConfig = Field(default_factory=PolicyRefConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    ignore: IgnoreConfig = Field(default_factory=IgnoreConfig)

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: int) -> int:
        if v != 1:
            raise ValueError(f"Unsupported configuration version: {v}. Only version 1 is supported.")
        return v

    def canonical_dict(self) -> dict[str, Any]:
        """Convert configuration to deterministic, canonically ordered dictionary."""
        return {
            "version": self.version,
            "project": {
                "name": self.project.name,
                "id": self.project.id,
            },
            "analysis": {
                "languages": sorted(self.analysis.languages),
                "exclude": sorted(self.analysis.exclude),
            },
            "scoring": {
                "baseline": self.scoring.baseline,
                "baseline_file": self.scoring.baseline_file,
            },
            "policy": {
                "file": self.policy.file,
            },
            "output": {
                "format": self.output.format,
            },
            "ignore": {
                "rules": sorted(self.ignore.rules),
                "findings": sorted(self.ignore.findings),
            },
        }

    def compute_hash(self) -> str:
        """Compute deterministic SHA-256 hash of the canonical configuration."""
        canonical = self.canonical_dict()
        serialized = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


def parse_entropy_config(
    content: str | dict[str, Any],
    file_path: Path | str = ".entropy.yml",
) -> EntropyProjectConfig:
    """Parse and validate .entropy.yml content safely."""
    raw_data: Any
    if isinstance(content, str):
        try:
            raw_data = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            raise ValueError(f"Malformed YAML in '{file_path}': {exc}") from exc
    elif isinstance(content, dict):
        raw_data = content
    else:
        raise ValueError(f"Invalid configuration input type: {type(content)}")

    if not isinstance(raw_data, dict):
        raise ValueError(f"Configuration in '{file_path}' must be a YAML mapping/dictionary.")

    return EntropyProjectConfig.model_validate(raw_data)


def load_project_config(repo_root: Path | str) -> EntropyProjectConfig | None:
    """Load and parse .entropy.yml from repository root if it exists."""
    root = Path(repo_root).resolve()
    for name in [".entropy.yml", ".entropy.yaml"]:
        cfg_file = root / name
        if cfg_file.is_file():
            text = cfg_file.read_text(encoding="utf-8")
            return parse_entropy_config(text, file_path=cfg_file)
    return None

"""Base abstraction for language-specific static analysis adapters.

Isolates parser, internal rule checks, and optional external security tool integrations
behind a consistent, normalized finding interface.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.models.domain.enums import DebtCategory, SupportedLanguage
from app.models.domain.finding import Finding
from app.models.domain.rule import RuleDefinition
from app.parser.base import ParsedFile

logger = logging.getLogger("entropy.analyzers.adapters")


@dataclass
class ToolStatus:
    """Status and availability of an optional external security tool or linter."""

    tool_name: str
    available: bool
    path: str | None = None
    version: str | None = None
    message: str | None = None


class BaseLanguageAdapter(ABC):
    """Abstract base class for language analysis adapters.

    Each adapter encapsulates:
    1. Reliable detection and language identification.
    2. Zero-execution, deterministic internal static analysis rules.
    3. Optional external tool discovery and safe execution when available.
    4. Mapping all outputs into normalized Entropy Finding domain objects.
    """

    @property
    @abstractmethod
    def language(self) -> SupportedLanguage:
        """The primary programming language supported by this adapter."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable adapter name."""
        pass

    @property
    @abstractmethod
    def supported_categories(self) -> set[DebtCategory]:
        """Entropy debt categories covered by this adapter's rules."""
        pass

    @property
    @abstractmethod
    def rules(self) -> list[RuleDefinition]:
        """List of all rules implemented and enforced by this adapter."""
        pass

    @abstractmethod
    def analyze_file(self, file: ParsedFile) -> list[Finding]:
        """Execute deterministic static analysis on a single parsed file.

        Args:
            file: ParsedFile containing source code, lines, and metadata.

        Returns:
            list[Finding]: Normalized findings detected in the file.
        """
        pass

    def analyze_files(self, files: list[ParsedFile]) -> list[Finding]:
        """Analyze a collection of files belonging to this language.

        Default implementation processes files sequentially with error isolation.
        """
        findings: list[Finding] = []
        for file in files:
            if not file.is_valid and not file.source_code:
                continue
            try:
                file_findings = self.analyze_file(file)
                findings.extend(file_findings)
            except Exception as exc:
                logger.error(
                    "Adapter '%s' encountered error analyzing '%s': %s",
                    self.name,
                    file.relative_path,
                    exc,
                    exc_info=True,
                )
        return findings

    def check_tool_availability(self) -> ToolStatus:
        """Check whether the optional external tool for this language is installed and accessible.

        Default implementation returns an internal-only status. Subclasses override
        to probe PATH for optional linters or tools (e.g. cppcheck, cargo-audit, gosec, psalm).
        """
        return ToolStatus(
            tool_name="internal_static_engine",
            available=True,
            message="Using built-in deterministic static analysis engine",
        )

    @staticmethod
    def probe_executable(cmd_name: str, version_arg: str = "--version") -> ToolStatus:
        """Helper to safely check if an executable exists on the system PATH without side effects."""
        path = shutil.which(cmd_name)
        if not path:
            return ToolStatus(
                tool_name=cmd_name,
                available=False,
                message=f"'{cmd_name}' was not found on PATH. Optional tool integration is disabled; using internal static analyzer.",
            )

        version_str: str | None = None
        try:
            res = subprocess.run(
                [path, version_arg],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            first_line = (res.stdout or res.stderr or "").splitlines()
            if first_line:
                version_str = first_line[0].strip()
        except Exception:
            pass

        return ToolStatus(
            tool_name=cmd_name,
            available=True,
            path=path,
            version=version_str,
            message=f"'{cmd_name}' is installed and available",
        )

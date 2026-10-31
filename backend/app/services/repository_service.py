"""Repository service coordinating repository scans, state tracking, and manifest retrieval."""

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from app.core.config import settings
from app.core.errors import (
    RepositoryError,
    RepositoryLimitExceededError,
    RepositoryNotADirectoryError,
    RepositoryNotFoundError,
    RepositoryPermissionError,
    RepositorySecurityError,
)
from app.core.logging import logger
from app.models.domain.enums import ScanStatus, SupportedLanguage
from app.models.domain.manifest import RepositoryManifest
from app.models.domain.scan import RepositoryMetadata, RepositoryScanResult
from app.parser.base import ParsedFile
from app.parser.jsts.models import ParsedJSTSUnit
from app.parser.jsts.parser import JSTSParser
from app.parser.python.models import ParsedPythonUnit
from app.parser.python.parser import PythonParser
from app.persistence.database import scan_db
from app.repository.config import ScannerConfig
from app.repository.language import ALL_SUPPORTED_LANGUAGES
from app.repository.scanner import RepositoryScanner
from app.repository.sources import LocalRepositorySource, RepositorySource

_scans_store: dict[str, RepositoryScanResult] = {}


class RepositoryService:
    """Service orchestrating repository ingestion, tracking state, and persisting results."""

    def __init__(
        self,
        config: ScannerConfig | None = None,
        store: dict[str, RepositoryScanResult] | None = None,
    ):
        self.config = config or ScannerConfig(
            max_file_size_bytes=settings.MAX_FILE_SIZE_BYTES,
            max_file_count=settings.MAX_FILES_COUNT,
            max_repo_size_bytes=settings.MAX_REPO_SIZE_BYTES,
            respect_gitignore=settings.RESPECT_GITIGNORE,
            follow_symlinks=settings.FOLLOW_SYMLINKS,
            analyzable_languages=set(ALL_SUPPORTED_LANGUAGES),
        )
        self.scanner = RepositoryScanner(self.config)
        self._scans = store if store is not None else _scans_store

    def execute_scan(
        self,
        repo_path: str | Path | None = None,
        repo_name: str | None = None,
        check_allowed_roots: bool = True,
        include_tests: bool = False,
        source: RepositorySource | None = None,
        languages: set[SupportedLanguage] | list[str] | None = None,
    ) -> RepositoryScanResult:
        """Execute a safe repository scan, record state transitions, and return the result."""
        if source is None:
            if not repo_path:
                raise RepositoryNotFoundError("Repository path or source must be provided.")
            clean_path = str(repo_path).strip()
            is_git_url = clean_path.lower().startswith(("http://", "https://"))

            if is_git_url:
                from app.repository.sources import GitUrlRepositorySource

                source = GitUrlRepositorySource(clean_path, repo_name)
            else:
                source = LocalRepositorySource(clean_path, repo_name, check_allowed_roots=check_allowed_roots)

        # Pre-validate source to fail fast on invalid paths or permissions
        try:
            source.validate()
        except (
            RepositoryNotFoundError,
            RepositoryNotADirectoryError,
            RepositoryPermissionError,
            RepositorySecurityError,
            RepositoryLimitExceededError,
        ) as err:
            logger.error("Repository validation failed for '%s': %s", repo_name or repo_path, err)
            raise

        scan_id = str(uuid4())
        started_at = datetime.now(UTC)

        # Initial state: SCANNING
        initial_record = RepositoryScanResult(
            scan_id=scan_id,
            repository=RepositoryMetadata(
                name=source.get_name(),
                path=str(source.get_root_path()),
                total_files=0,
                scannable_files=0,
                total_loc=0,
                excluded_files=0,
                excluded_loc=0,
            ),
            status=ScanStatus.SCANNING,
            manifest=None,
            findings=[],
            score=None,
            started_at=started_at,
            errors=[],
        )
        self._scans[scan_id] = initial_record

        config_obj = None
        try:
            from app.core.project_config import load_project_config

            config_obj = load_project_config(source.get_root_path())
        except Exception as exc:
            logger.warning("Failed to load project config for '%s': %s", repo_path, exc)

        effective_include_tests = include_tests or (
            config_obj.analysis.include_tests if config_obj else False
        )
        custom_excludes = config_obj.analysis.exclude if config_obj else []

        selected_langs: set[SupportedLanguage] | None = None
        if languages:
            selected_langs = {
                SupportedLanguage(l.lower()) if isinstance(l, str) else l
                for l in languages
            }
        elif config_obj and config_obj.analysis.languages:
            selected_langs = {
                SupportedLanguage(l.lower())
                for l in config_obj.analysis.languages
                if l.lower() in [s.value for s in SupportedLanguage]
            }
        else:
            selected_langs = set(ALL_SUPPORTED_LANGUAGES)

        cfg = ScannerConfig(
            max_file_size_bytes=self.config.max_file_size_bytes,
            max_file_count=self.config.max_file_count,
            max_repo_size_bytes=self.config.max_repo_size_bytes,
            respect_gitignore=self.config.respect_gitignore,
            follow_symlinks=self.config.follow_symlinks,
            include_tests=effective_include_tests,
            excluded_paths=list(self.config.excluded_paths),
            custom_exclude_patterns=custom_excludes,
            analyzable_languages=selected_langs,
        )
        scanner_to_use = RepositoryScanner(cfg)

        try:
            scan_result = scanner_to_use.scan(source)
            if config_obj:
                scan_result.config_hash = config_obj.compute_hash()
                scan_result.project_id = config_obj.project.id or config_obj.project.name
                scan_result.repository.project_id = scan_result.project_id
                if config_obj.project.name:
                    scan_result.repository.name = config_obj.project.name

            self._scans[scan_result.scan_id] = scan_result
            scan_db.save_scan(scan_result)
            return scan_result
        except Exception as e:
            logger.exception("Scan execution failed for repository '%s': %s", repo_path, e)
            initial_record.status = ScanStatus.FAILED
            initial_record.completed_at = datetime.now(UTC)
            initial_record.errors.append(str(e))
            self._scans[scan_id] = initial_record
            scan_db.save_scan(initial_record)
            if isinstance(e, RepositoryError):
                raise
            raise RepositoryError(f"Unexpected scanner failure: {e}") from e

    def save_scan(self, scan: RepositoryScanResult) -> None:
        """Persist or update scan in memory and database."""
        self._scans[scan.scan_id] = scan
        scan_db.save_scan(scan)

    def get_scan(self, scan_id: str) -> RepositoryScanResult | None:
        """Retrieve a stored scan result by its ID."""
        scan = self._scans.get(scan_id)
        if not scan:
            scan = scan_db.get_scan(scan_id)
            if scan:
                self._scans[scan_id] = scan
        return scan

    def get_manifest(self, scan_id: str) -> RepositoryManifest | None:
        """Retrieve the repository manifest for a scan."""
        scan = self.get_scan(scan_id)
        if not scan:
            return None
        return scan.manifest

    def list_scans(self) -> list[RepositoryScanResult]:
        """List all scans ordered from most recent to oldest."""
        return sorted(self._scans.values(), key=lambda s: s.started_at, reverse=True)

    def parse_python_files(self, scan_id: str) -> list[ParsedPythonUnit]:
        """Parse all Python files discovered in a scan's manifest into ParsedPythonUnits."""
        scan = self.get_scan(scan_id)
        if not scan or not scan.manifest:
            return []

        parser = PythonParser()
        units: list[ParsedPythonUnit] = []
        root_path = Path(scan.repository.path)

        for file_meta in scan.manifest.files:
            # Strictly filter: only parse Python files that are marked for analysis
            if not getattr(file_meta, "analysis_supported", True):
                continue
            if file_meta.language.lower() != "python":
                continue

            file_abs_path = root_path / file_meta.path
            unit = parser.parse_file(
                file_path=file_abs_path,
                relative_path=file_meta.path,
                language=SupportedLanguage.PYTHON,
            )
            units.append(unit)

        return units

    def parse_jsts_files(self, scan_id: str) -> list[ParsedJSTSUnit]:
        """Parse all JavaScript and TypeScript files discovered in a scan's manifest into ParsedJSTSUnits."""
        scan = self.get_scan(scan_id)
        if not scan or not scan.manifest:
            return []

        parser = JSTSParser()
        units: list[ParsedJSTSUnit] = []
        root_path = Path(scan.repository.path)

        for file_meta in scan.manifest.files:
            if not getattr(file_meta, "analysis_supported", True):
                continue
            lang_str = file_meta.language.lower()
            if lang_str not in ("javascript", "typescript"):
                continue

            lang = (
                SupportedLanguage.JAVASCRIPT
                if lang_str == "javascript"
                else SupportedLanguage.TYPESCRIPT
            )
            file_abs_path = root_path / file_meta.path
            unit = parser.parse_file(
                file_path=file_abs_path,
                relative_path=file_meta.path,
                language=lang,
            )
            units.append(unit)

        return units

    def parse_other_language_files(
        self, scan_id: str, languages: set[SupportedLanguage] | None = None
    ) -> list[ParsedFile]:
        """Safely parse/load all non-Python, non-JS/TS source files discovered in a scan's manifest into ParsedFiles."""
        scan = self.get_scan(scan_id)
        if not scan or not scan.manifest:
            return []

        parsed_files: list[ParsedFile] = []
        root_path = Path(scan.repository.path)

        for file_meta in scan.manifest.files:
            if not getattr(file_meta, "analysis_supported", True):
                continue
            lang_str = file_meta.language.lower()
            if lang_str in ("python", "javascript", "typescript", "unknown"):
                continue

            try:
                lang = SupportedLanguage(lang_str)
            except ValueError:
                continue

            if languages is not None and lang not in languages:
                continue

            file_abs_path = root_path / file_meta.path
            try:
                source_bytes = file_abs_path.read_bytes()
            except OSError as err:
                parsed_files.append(
                    ParsedFile(
                        absolute_path=file_abs_path,
                        relative_path=file_meta.path,
                        language=lang,
                        source_code="",
                        lines=[],
                        parse_errors=[f"Read error: {err}"],
                    )
                )
                continue

            try:
                source_code = source_bytes.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    source_code = source_bytes.decode("latin-1")
                except Exception as err:
                    parsed_files.append(
                        ParsedFile(
                            absolute_path=file_abs_path,
                            relative_path=file_meta.path,
                            language=lang,
                            source_code="",
                            lines=[],
                            parse_errors=[f"Encoding error: {err}"],
                        )
                    )
                    continue

            lines = source_code.splitlines(keepends=True)
            parsed_files.append(
                ParsedFile(
                    absolute_path=file_abs_path,
                    relative_path=file_meta.path,
                    language=lang,
                    source_code=source_code,
                    lines=lines,
                )
            )

        return parsed_files

    def parse_python_file(
        self, scan_id: str, relative_path: str
    ) -> ParsedPythonUnit | None:
        """Parse a single Python file from a scan's manifest."""
        scan = self.get_scan(scan_id)
        if not scan or not scan.manifest:
            return None

        # Verify file is in manifest
        file_meta = next((f for f in scan.manifest.files if f.path == relative_path), None)
        if not file_meta:
            return None

        parser = PythonParser()
        root_path = Path(scan.repository.path)
        file_abs_path = root_path / relative_path

        lang = (
            SupportedLanguage.PYTHON
            if file_meta.language.lower() == "python"
            else SupportedLanguage.UNKNOWN
        )
        return parser.parse_file(
            file_path=file_abs_path,
            relative_path=relative_path,
            language=lang,
        )

    def parse_jsts_file(
        self, scan_id: str, relative_path: str
    ) -> ParsedJSTSUnit | None:
        """Parse a single JavaScript or TypeScript file from a scan's manifest."""
        scan = self.get_scan(scan_id)
        if not scan or not scan.manifest:
            return None

        file_meta = next((f for f in scan.manifest.files if f.path == relative_path), None)
        if not file_meta:
            return None

        lang_str = file_meta.language.lower()
        if lang_str not in ("javascript", "typescript"):
            return None

        parser = JSTSParser()
        root_path = Path(scan.repository.path)
        file_abs_path = root_path / relative_path

        lang = (
            SupportedLanguage.JAVASCRIPT
            if lang_str == "javascript"
            else SupportedLanguage.TYPESCRIPT
        )
        return parser.parse_file(
            file_path=file_abs_path,
            relative_path=relative_path,
            language=lang,
        )


repository_service = RepositoryService()

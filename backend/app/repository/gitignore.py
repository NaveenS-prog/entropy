"""Gitignore pattern parsing and path matching."""

import re
from pathlib import Path


class GitIgnoreRule:
    """Represents a single rule parsed from a .gitignore file."""

    def __init__(self, raw_pattern: str, base_rel_dir: str = ""):
        self.raw_pattern = raw_pattern.strip()
        self.base_rel_dir = base_rel_dir.strip("/").replace("\\", "/")

        pattern = self.raw_pattern
        self.is_negation = pattern.startswith("!")
        if self.is_negation:
            pattern = pattern[1:]

        self.directory_only = pattern.endswith("/")
        if self.directory_only:
            pattern = pattern[:-1]

        # Check if rule is anchored
        if pattern.startswith("/"):
            pattern = pattern[1:]
            self.anchored = True
        elif "/" in pattern:
            self.anchored = True
        else:
            self.anchored = False

        self.pattern = pattern
        self.regex = self._compile_to_regex(pattern, self.anchored, self.base_rel_dir)

    def _compile_to_regex(self, pattern: str, anchored: bool, base_rel_dir: str) -> re.Pattern:
        parts: list[str] = ["^"]

        if base_rel_dir:
            parts.append(re.escape(base_rel_dir) + "/")

        if not anchored:
            parts.append(r"(?:.*/)?")

        i = 0
        n = len(pattern)
        while i < n:
            c = pattern[i]
            if c == "*":
                if i + 1 < n and pattern[i + 1] == "*":
                    if i + 2 < n and pattern[i + 2] == "/":
                        parts.append(r"(?:.*/)?")
                        i += 3
                        continue
                    else:
                        parts.append(r".*")
                        i += 2
                        continue
                else:
                    parts.append(r"[^/]*")
                    i += 1
            elif c == "?":
                parts.append(r"[^/]")
                i += 1
            elif c == "[":
                j = i + 1
                if j < n and pattern[j] == "!":
                    j += 1
                if j < n and pattern[j] == "]":
                    j += 1
                while j < n and pattern[j] != "]":
                    j += 1
                if j >= n:
                    parts.append(r"\[")
                    i += 1
                else:
                    stuff = pattern[i + 1 : j].replace("\\", "\\\\")
                    i = j + 1
                    if stuff.startswith("!"):
                        stuff = "^" + stuff[1:]
                    parts.append(f"[{stuff}]")
            else:
                parts.append(re.escape(c))
                i += 1

        parts.append(r"(?:/.*)?$")
        return re.compile("".join(parts))

    def evaluate(self, rel_path: str, is_dir: bool = False) -> bool | None:
        """Evaluate if the path matches this rule.

        Returns True (ignore), False (un-ignore via negation), or None (no match).
        """
        norm_path = rel_path.strip("/").replace("\\", "/")
        if self.directory_only and not is_dir and not self._is_ancestor_match(norm_path):
            return None

        if self.regex.match(norm_path):
            return not self.is_negation
        return None

    def _is_ancestor_match(self, path: str) -> bool:
        # If directory_only is true, see if regex matches any directory prefix
        parts = path.split("/")
        for i in range(1, len(parts)):
            prefix = "/".join(parts[:i])
            if self.regex.match(prefix):
                return True
        return False


class GitIgnoreMatcher:
    """Collects rules from .gitignore files across the repository tree."""

    def __init__(self, root_dir: Path | str | None = None):
        self.root_dir = Path(root_dir).resolve() if root_dir else None
        self.rules: list[GitIgnoreRule] = []

    @classmethod
    def from_root(cls, root_dir: Path | str) -> "GitIgnoreMatcher":
        """Factory creating a matcher and parsing root .gitignore if present."""
        matcher = cls(root_dir)
        root = Path(root_dir).resolve()
        gitignore_path = root / ".gitignore"
        if gitignore_path.is_file():
            matcher.parse_file(gitignore_path, base_rel_dir="")
        return matcher

    def parse_file(self, gitignore_path: Path, base_rel_dir: str = "") -> None:
        """Parse rules from a .gitignore file."""
        try:
            with open(gitignore_path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    self.rules.append(GitIgnoreRule(stripped, base_rel_dir=base_rel_dir))
        except OSError:
            pass

    def add_pattern(self, pattern: str, base_rel_dir: str = "") -> None:
        """Add an individual ignore pattern."""
        self.rules.append(GitIgnoreRule(pattern, base_rel_dir=base_rel_dir))

    def is_ignored(self, rel_path: str, is_dir: bool = False) -> bool:
        """Determine if a relative path is ignored by matching against all rules."""
        ignored = False
        for rule in self.rules:
            result = rule.evaluate(rel_path, is_dir=is_dir)
            if result is not None:
                ignored = result
        return ignored

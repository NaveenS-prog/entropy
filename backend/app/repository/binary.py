"""Binary file detection utilities."""

from pathlib import Path


def is_binary_extension(path: Path | str, binary_extensions: set[str]) -> bool:
    """Check if file suffix matches known binary extensions."""
    suffix = Path(path).suffix.lower()
    return suffix in binary_extensions


def is_binary_content(path: Path | str, probe_size_bytes: int = 8192) -> bool:
    """Inspect the first bytes of a file to check for null bytes or binary characters.

    Standard heuristic: if null byte (b'\\0') exists in the initial probe bytes,
    it is almost certainly a binary / non-text file.
    """
    try:
        with open(path, "rb") as f:
            chunk = f.read(probe_size_bytes)
            if b"\x00" in chunk:
                return True
        return False
    except (OSError, PermissionError):
        return False

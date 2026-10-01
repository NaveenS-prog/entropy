"""A simple Python module for testing basic AST extraction."""

import os
import sys
from typing import List, Optional

VERSION = "1.0.0"
DEBUG = False


def get_version(prefix: Optional[str] = None) -> str:
    """Return the formatted version string."""
    if prefix:
        return f"{prefix}-{VERSION}"
    return VERSION

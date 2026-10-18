"""Test that each top-level module in app can be imported in isolation in a fresh subprocess."""

import os
import subprocess
import sys
from pathlib import Path


def test_each_module_imports_cleanly_in_fresh_subprocess():
    """Verify no circular imports or startup errors occur when importing any module first."""
    app_dir = Path(__file__).resolve().parents[2] / "app"
    backend_dir = app_dir.parent

    # Collect all top-level modules and packages directly under app
    modules = []
    for item in sorted(app_dir.iterdir()):
        if item.name.startswith("__"):
            continue
        if item.is_dir() and (item / "__init__.py").exists():
            modules.append(f"app.{item.name}")
        elif item.is_file() and item.suffix == ".py":
            modules.append(f"app.{item.stem}")

    # Explicitly test specific modules identified in the circular import bug
    for target in [
        "app.services.scan_service",
        "app.persistence.database",
        "app.comparison.service",
        "app.github.client",
    ]:
        if target not in modules:
            modules.append(target)

    env = os.environ.copy()
    env["PYTHONPATH"] = str(backend_dir)

    for mod in modules:
        proc = subprocess.run(
            [sys.executable, "-c", f"import {mod}"],
            cwd=str(backend_dir),
            env=env,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, (
            f"Failed to import '{mod}' in fresh subprocess:\n"
            f"STDOUT:\n{proc.stdout}\n"
            f"STDERR:\n{proc.stderr}"
        )

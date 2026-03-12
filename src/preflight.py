from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from src.termui import log


class PreflightError(RuntimeError):
    pass


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def run_preflight() -> None:
    log.phase("Running mandatory preflight checks")
    _run_step(
        name="ruff",
        command=[sys.executable, "-m", "ruff", "check", "main.py", "src", "tests"],
    )
    _run_step(
        name="tests",
        command=[sys.executable, "-m", "unittest", "discover", "-s", "tests"],
    )
    log.success("Preflight checks passed: lint + tests are green")


def _run_step(name: str, command: list[str]) -> None:
    completed = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        stdout = completed.stdout.strip()
        details = stderr or stdout or f"{name} failed with exit code {completed.returncode}"
        if "No module named ruff" in details:
            details = "ruff is not installed in the active environment; run `uv sync` first"
        raise PreflightError(details)
    if name == "ruff":
        log.success("Lint check passed")
    elif name == "tests":
        log.success("Unit tests passed")

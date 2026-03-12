from __future__ import annotations

import sys
import threading
from datetime import datetime


class TerminalLogger:
    COLORS = {
        "reset": "\033[0m",
        "dim": "\033[2m",
        "cyan": "\033[36m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "red": "\033[31m",
        "magenta": "\033[35m",
    }

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._use_color = sys.stderr.isatty()
        self._verbose = False

    def configure(self, *, verbose: bool) -> None:
        self._verbose = verbose

    def phase(self, message: str) -> None:
        self._emit("cyan", "[PHASE]", message)

    def info(self, message: str) -> None:
        if not self._verbose:
            return
        self._emit("magenta", "[INFO ]", message)

    def nmap(self, message: str) -> None:
        self._emit("green", "[NMAP ]", message)

    def success(self, message: str) -> None:
        self._emit("green", "[ OK  ]", message)

    def warn(self, message: str) -> None:
        self._emit("yellow", "[WARN ]", message)

    def error(self, message: str) -> None:
        self._emit("red", "[FAIL ]", message)

    def _emit(self, color: str, prefix: str, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"{timestamp} {prefix} {message}"
        with self._lock:
            if self._use_color:
                prefix_colored = f"{self.COLORS[color]}{prefix}{self.COLORS['reset']}"
                timestamp_colored = f"{self.COLORS['dim']}{timestamp}{self.COLORS['reset']}"
                line = f"{timestamp_colored} {prefix_colored} {message}"
            print(line, file=sys.stderr, flush=True)


log = TerminalLogger()

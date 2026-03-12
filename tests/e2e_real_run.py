from __future__ import annotations

import json
import socket
import subprocess
import tempfile
import threading
import unittest
from contextlib import closing
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class QuietHandler(SimpleHTTPRequestHandler):
    def handle(self) -> None:
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):
            return

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return


class LocalHttpServer:
    def __init__(self, port: int = 0) -> None:
        self._server = ThreadingHTTPServer(("127.0.0.1", port), QuietHandler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="nmaper-e2e-http",
            daemon=True,
        )

    @property
    def port(self) -> int:
        return int(self._server.server_port)

    def __enter__(self) -> "LocalHttpServer":
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def _reserve_free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _run_cli(*args: object) -> subprocess.CompletedProcess[str]:
    command = ["uv", "run", "nmaper", *[str(arg) for arg in args]]
    completed = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        timeout=240,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "command failed\n"
            f"command: {' '.join(command)}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    return completed


class RealRunE2ETests(unittest.TestCase):
    def test_cli_scan_and_read_only_analytics(self) -> None:
        second_port = _reserve_free_port()
        with tempfile.TemporaryDirectory(prefix="nmaper-e2e-") as temp_dir:
            temp_path = Path(temp_dir)
            db_path = temp_path / "e2e.db"
            scan_ports = f"{second_port}"

            with LocalHttpServer() as first_server:
                scan_ports = f"{first_server.port},{second_port}"
                _run_cli(
                    "127.0.0.1/32",
                    "-p",
                    scan_ports,
                    "--no-ping",
                    "--service-version",
                    "--detail-workers",
                    "1",
                    "--db",
                    db_path,
                    "--save",
                    "db",
                    "--name",
                    "e2e-first",
                )

            with LocalHttpServer(second_port):
                _run_cli(
                    "127.0.0.1/32",
                    "-p",
                    scan_ports,
                    "--no-ping",
                    "--service-version",
                    "--detail-workers",
                    "1",
                    "--db",
                    db_path,
                    "--save",
                    "db",
                    "--name",
                    "e2e-second",
                )

            sessions_output = _run_cli("--sessions", "--db", db_path, "--limit", "5").stdout
            self.assertIn("#1", sessions_output)
            self.assertIn("#2", sessions_output)

            session_payload = json.loads(
                _run_cli("--session", "1", "--db", db_path, "--out", "json").stdout
            )
            self.assertEqual(session_payload["session"]["id"], 1)
            self.assertEqual(session_payload["session"]["target"], "127.0.0.1/32")
            self.assertGreaterEqual(len(session_payload["hosts"]), 1)

            host_payload = json.loads(
                _run_cli(
                    "--session",
                    "1",
                    "--host",
                    "127001",
                    "--db",
                    db_path,
                    "--out",
                    "json",
                ).stdout
            )
            self.assertEqual(len(host_payload["hosts"]), 1)

            diff_payload = json.loads(
                _run_cli("--diff", "1", "2", "--db", db_path, "--out", "json").stdout
            )
            self.assertTrue(diff_payload["changed_hosts"])

            global_payload = json.loads(
                _run_cli("--diff-global", "--db", db_path, "--out", "json").stdout
            )
            self.assertEqual(global_payload["session_ids"], [2, 1])

            devices_payload = json.loads(
                _run_cli("--devices", "--db", db_path, "--out", "json").stdout
            )
            self.assertGreaterEqual(devices_payload["unique_devices"], 1)

            device_payload = json.loads(
                _run_cli("--device", "127001", "--db", db_path, "--out", "json").stdout
            )
            self.assertTrue(device_payload["matches"])

            timeline_payload = json.loads(
                _run_cli("--timeline", "--db", db_path, "--out", "json").stdout
            )
            self.assertEqual(len(timeline_payload["entries"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)

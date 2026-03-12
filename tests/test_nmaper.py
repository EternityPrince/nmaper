from __future__ import annotations

import unittest
from pathlib import Path

from src.cli import parse_args
from src.model import ScanOptions
from src.nmaper import _render_command, build_detail_command, build_discovery_command


class NmaperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.options = ScanOptions(
            target="192.168.0.0/24",
            dev_mode=False,
            check_only=False,
            list_sessions=False,
            diff_ids=None,
            diff_global=False,
            devices_mode=False,
            device_query=None,
            session_mode=False,
            session_id=None,
            host_query=None,
            delete_id=None,
            timeline_mode=False,
            limit=10,
            out_format="clipboard",
            out_path=None,
            status_filter=None,
            target_filter=None,
            vendor_filter=None,
            mac_only=False,
            ip_only=False,
            ports="22,80,443",
            output=Path("scans"),
            db_path=None,
            save_mode="db",
            verbose=False,
            name=None,
            timing="3",
            top_ports=None,
            no_ping=False,
            service_version=False,
            os_detect=False,
            use_sudo=True,
            detail_workers=4,
        )

    def test_render_command_formats_shell_command(self) -> None:
        rendered = _render_command(["sudo", "-n", "nmap", "-sS", "192.168.0.0/24", "-oX", "-"])

        self.assertEqual(rendered, "sudo -n nmap -sS 192.168.0.0/24 -oX -")

    def test_build_discovery_command_uses_scan_options(self) -> None:
        command = build_discovery_command(self.options)

        self.assertEqual(
            command,
            [
                "sudo",
                "-n",
                "nmap",
                "-sS",
                "192.168.0.0/24",
                "-T",
                "3",
                "-oX",
                "-",
                "-p",
                "22,80,443",
            ],
        )

    def test_build_detail_command_defaults_to_aggressive_scan(self) -> None:
        command = build_detail_command(self.options, "192.168.0.1", [22, 80])

        self.assertEqual(
            command,
            ["sudo", "-n", "nmap", "192.168.0.1", "-T", "3", "-oX", "-", "-p", "22,80", "-A"],
        )

    def test_parse_args_accepts_verbose_flag(self) -> None:
        args = parse_args(["192.168.0.0/24", "--verbose"])

        self.assertTrue(args.verbose)
        self.assertEqual(args.save_mode, "db")

    def test_parse_args_supports_check_mode_without_target(self) -> None:
        args = parse_args(["--check"])

        self.assertTrue(args.check_only)
        self.assertIsNone(args.target)

    def test_parse_args_supports_dev_mode(self) -> None:
        args = parse_args(["192.168.0.0/24", "--dev"])

        self.assertTrue(args.dev_mode)
        self.assertEqual(args.target, "192.168.0.0/24")

    def test_parse_args_supports_diff_mode(self) -> None:
        args = parse_args(["--diff", "1", "2"])

        self.assertEqual(args.diff_ids, (1, 2))
        self.assertTrue(args.target is None)

    def test_parse_args_supports_global_diff_mode(self) -> None:
        args = parse_args(["--diff-global", "--limit", "7"])

        self.assertTrue(args.diff_global)
        self.assertEqual(args.limit, 7)

    def test_parse_args_supports_devices_mode(self) -> None:
        args = parse_args(["--devices", "--limit", "9"])

        self.assertTrue(args.devices_mode)
        self.assertEqual(args.limit, 9)

    def test_parse_args_supports_device_query_mode(self) -> None:
        args = parse_args(["--device", "tp", "--vendor", "tp"])

        self.assertEqual(args.device_query, "tp")
        self.assertEqual(args.vendor_filter, "tp")

    def test_parse_args_supports_timeline_mode(self) -> None:
        args = parse_args(["--timeline", "--status", "completed"])

        self.assertTrue(args.timeline_mode)
        self.assertEqual(args.status_filter, "completed")

    def test_parse_args_accepts_out_format(self) -> None:
        args = parse_args(["--session", "7", "--out", "json"])

        self.assertEqual(args.out_format, "json")
        self.assertIsNone(args.out_path)
        self.assertEqual(args.session_id, 7)

    def test_parse_args_accepts_file_output(self) -> None:
        args = parse_args(["--session", "7", "--out", "file:reports/session-7.md"])

        self.assertEqual(args.out_format, "md")
        self.assertEqual(args.out_path, Path("reports/session-7.md"))

    def test_parse_args_supports_sessions_mode_without_target(self) -> None:
        args = parse_args(["--sessions", "--limit", "5"])

        self.assertTrue(args.list_sessions)
        self.assertFalse(args.session_mode)
        self.assertIsNone(args.target)
        self.assertEqual(args.limit, 5)

    def test_parse_args_supports_session_detail_mode(self) -> None:
        args = parse_args(["--session", "7", "--host", "192.168.0.1"])

        self.assertTrue(args.session_mode)
        self.assertEqual(args.session_id, 7)
        self.assertEqual(args.host_query, "192.168.0.1")
        self.assertFalse(args.list_sessions)

    def test_parse_args_supports_session_list_mode_without_id(self) -> None:
        args = parse_args(["--session"])

        self.assertTrue(args.session_mode)
        self.assertIsNone(args.session_id)
        self.assertFalse(args.list_sessions)

    def test_parse_args_supports_session_delete_mode(self) -> None:
        args = parse_args(["--session", "--del", "-1"])

        self.assertTrue(args.session_mode)
        self.assertEqual(args.delete_id, -1)


if __name__ == "__main__":
    unittest.main()

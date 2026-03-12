from __future__ import annotations

from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser, RawDescriptionHelpFormatter
from pathlib import Path

from src.model import ScanOptions


class HelpFormatter(ArgumentDefaultsHelpFormatter, RawDescriptionHelpFormatter):
    pass


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="nmaper",
        description=(
            "Map a network, keep the evidence, and explore how it changes over time.\n\n"
            "nmaper runs discovery + host detail scans, stores snapshots in SQLite, "
            "and gives you fast read-only analysis for sessions, devices, diffs, and timelines."
        ),
        epilog=(
            "Examples:\n"
            "  nmaper 192.168.0.0/24 --sudo\n"
            "  nmaper 192.168.0.0/24 -p 22,80,443 --service-version --save db\n"
            "  nmaper --session 12 --out md\n"
            "  nmaper --session 12 --out file:reports/session-12.md\n"
            "  nmaper --device tp --vendor tp --mac-only\n"
            "  nmaper --diff 12 18 --out json\n"
            "  nmaper --timeline --limit 20\n"
            "  nmaper --check"
        ),
        formatter_class=HelpFormatter,
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Target network, host, or CIDR block to scan. Example: 192.168.1.0/24",
    )

    mode_group = parser.add_argument_group("Explore Modes")
    mode_group.add_argument(
        "--sessions",
        action="store_true",
        help="List saved scan sessions.",
    )
    mode_group.add_argument(
        "--session",
        nargs="?",
        type=int,
        const=-1,
        default=None,
        help="Show one saved session by id. Without an id, lists saved sessions.",
    )
    mode_group.add_argument(
        "--host",
        default=None,
        help="Within --session <id>, focus on one host by IP or fuzzy host match.",
    )
    mode_group.add_argument(
        "--device",
        dest="device_query",
        default=None,
        help="Show the history of one device by MAC, IP, or fuzzy query.",
    )
    mode_group.add_argument(
        "--devices",
        action="store_true",
        help="Show analytics for unique devices and the most frequently seen devices.",
    )
    mode_group.add_argument(
        "--diff",
        nargs=2,
        type=int,
        metavar=("ID_1", "ID_2"),
        help="Compare two saved sessions.",
    )
    mode_group.add_argument(
        "--diff-global",
        action="store_true",
        help="Show broad movement across the latest saved sessions.",
    )
    mode_group.add_argument(
        "--timeline",
        action="store_true",
        help="Show chronological change summaries across saved sessions.",
    )

    filter_group = parser.add_argument_group("Filters")
    filter_group.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Maximum number of sessions or records to analyze.",
    )
    filter_group.add_argument(
        "--status",
        choices=["running", "completed", "failed"],
        default=None,
        help="Filter saved sessions by status.",
    )
    filter_group.add_argument(
        "--target-filter",
        default=None,
        help="Fuzzy filter for session targets. Short fragments like '1920' or 'lab' work.",
    )
    filter_group.add_argument(
        "--vendor",
        dest="vendor_filter",
        default=None,
        help="Fuzzy filter for device vendor names. 'tp' will match 'TP-Link'.",
    )
    filter_group.add_argument(
        "--mac-only",
        action="store_true",
        help="Only include devices backed by a MAC address.",
    )
    filter_group.add_argument(
        "--ip-only",
        action="store_true",
        help="Only include devices that currently have no MAC address.",
    )

    report_group = parser.add_argument_group("Reports")
    report_group.add_argument(
        "--out",
        default="clipboard",
        help=(
            "Report output for detailed read-only modes: clipboard, md, json, "
            "or file:<path>. File format is inferred from the extension "
            "(.md, .json, or plain text)."
        ),
    )
    report_group.add_argument(
        "--del",
        dest="delete_id",
        type=int,
        default=None,
        help="Delete one session by id. Use -1 to wipe the entire history after confirmation.",
    )

    scan_group = parser.add_argument_group("Scan Controls")
    port_group = scan_group.add_mutually_exclusive_group()
    port_group.add_argument(
        "-p",
        "--ports",
        default=None,
        help="Ports or ranges in native nmap syntax. Example: 22,80,443,8000-8100",
    )
    port_group.add_argument(
        "--top-ports",
        type=int,
        default=None,
        help="Scan only the N most common ports.",
    )
    scan_group.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("scans"),
        help="Directory for XML artifacts when --save xml is used.",
    )
    scan_group.add_argument(
        "--db",
        type=Path,
        default=None,
        help="Path to the SQLite database.",
    )
    scan_group.add_argument(
        "--save",
        choices=["db", "xml"],
        default="db",
        help="Persist scans to SQLite or keep raw XML files only.",
    )
    scan_group.add_argument(
        "-n",
        "--name",
        default=None,
        help="Human-friendly snapshot name. Defaults to a timestamp-based session id.",
    )
    scan_group.add_argument(
        "-T",
        "--timing",
        choices=["0", "1", "2", "3", "4", "5"],
        default="3",
        help="nmap timing template.",
    )
    scan_group.add_argument(
        "--no-ping",
        action="store_true",
        help="Skip host discovery and force nmap to treat targets as online.",
    )
    scan_group.add_argument(
        "--service-version",
        action="store_true",
        help="Run service/version detection on detailed host scans.",
    )
    scan_group.add_argument(
        "--os-detect",
        action="store_true",
        help="Run OS fingerprinting on detailed host scans.",
    )
    scan_group.add_argument(
        "--sudo",
        action="store_true",
        help="Warm sudo once, then run nmap with elevated privileges for SYN scanning.",
    )
    scan_group.add_argument(
        "--detail-workers",
        type=int,
        default=4,
        help="Maximum parallel host detail scans.",
    )

    runtime_group = parser.add_argument_group("Developer Workflow")
    runtime_group.add_argument(
        "--check",
        action="store_true",
        help="Run lint + tests and exit.",
    )
    runtime_group.add_argument(
        "--dev",
        action="store_true",
        help="Run lint + tests before executing the requested command.",
    )
    runtime_group.add_argument(
        "--verbose",
        action="store_true",
        help="Show verbose runtime logs.",
    )

    return parser


def parse_args(argv: list[str] | None = None) -> ScanOptions:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.detail_workers < 1:
        parser.error("--detail-workers must be >= 1")
    if args.limit < 1:
        parser.error("--limit must be >= 1")
    if args.mac_only and args.ip_only:
        parser.error("--mac-only and --ip-only cannot be used together")
    out_format, out_path = _parse_out_option(parser, args.out)

    primary_modes = [
        bool(args.sessions),
        args.session is not None,
        args.diff is not None,
        bool(args.diff_global),
        bool(args.devices),
        args.device_query is not None,
        bool(args.timeline),
    ]
    if sum(primary_modes) > 1:
        parser.error("choose only one explore mode at a time")

    archive_mode = any(primary_modes) or args.delete_id is not None

    if args.delete_id is not None and args.session is None:
        parser.error("--del must be used together with --session")
    if args.session is not None and args.session < -1:
        parser.error("--session id must be >= 1")
    if args.delete_id is not None and args.delete_id < -1:
        parser.error("--del id must be >= 1 or -1")
    if args.host and not (args.session and args.session > 0):
        parser.error("--host requires --session <id>")
    if args.vendor_filter and not (args.devices or args.device_query):
        parser.error("--vendor works with --devices or --device")
    if (args.mac_only or args.ip_only) and not (args.devices or args.device_query):
        parser.error("--mac-only/--ip-only work with --devices or --device")
    if not args.check and not archive_mode and not args.target:
        parser.error("target is required unless an explore mode or --check is used")
    if archive_mode and args.target:
        parser.error("target cannot be combined with explore modes")

    return ScanOptions(
        target=args.target,
        dev_mode=args.dev,
        check_only=args.check,
        list_sessions=args.sessions,
        diff_ids=tuple(args.diff) if args.diff else None,
        diff_global=args.diff_global,
        devices_mode=args.devices,
        device_query=args.device_query,
        session_mode=args.session is not None,
        session_id=args.session if args.session and args.session > 0 else None,
        host_query=args.host,
        delete_id=args.delete_id,
        timeline_mode=args.timeline,
        limit=args.limit,
        out_format=out_format,
        out_path=out_path,
        status_filter=args.status,
        target_filter=args.target_filter,
        vendor_filter=args.vendor_filter,
        mac_only=args.mac_only,
        ip_only=args.ip_only,
        ports=args.ports,
        output=args.output,
        db_path=args.db,
        save_mode=args.save,
        verbose=args.verbose,
        name=args.name,
        timing=args.timing,
        top_ports=args.top_ports,
        no_ping=args.no_ping,
        service_version=args.service_version,
        os_detect=args.os_detect,
        use_sudo=args.sudo,
        detail_workers=args.detail_workers,
    )


def _parse_out_option(parser: ArgumentParser, out_value: str) -> tuple[str, Path | None]:
    if out_value in {"clipboard", "md", "json"}:
        return out_value, None
    if not out_value.startswith("file:"):
        parser.error("--out must be one of clipboard, md, json, or file:<path>")
    raw_path = out_value.removeprefix("file:").strip()
    if not raw_path:
        parser.error("--out file:<path> requires a destination path")
    out_path = Path(raw_path).expanduser()
    suffix = out_path.suffix.lower()
    if suffix == ".json":
        return "json", out_path
    if suffix == ".md":
        return "md", out_path
    return "terminal", out_path

from __future__ import annotations

import sys
import time
from datetime import datetime

from src.cli import parse_args
from src.nmaper import run_scan, summarize_scan
from src.preflight import run_preflight
from src.termui import log


def main() -> int:
    app_started_at = time.monotonic()
    args = parse_args()
    log.configure(verbose=args.verbose)
    result = None
    log.phase("nmaper mission control online")
    if args.check_only:
        log.phase("Preflight-only request received")
    elif args.dev_mode:
        log.phase("Developer mode enabled")
    elif args.diff_ids is not None:
        log.phase(f"Session diff request received | ids={args.diff_ids[0]}->{args.diff_ids[1]}")
    elif args.diff_global:
        log.phase(f"Global dynamics request received | limit={args.limit}")
    elif args.devices_mode:
        log.phase(f"Device analytics request received | limit={args.limit}")
    elif args.device_query is not None:
        log.phase(f"Device history request received | query={args.device_query}")
    elif args.timeline_mode:
        log.phase(f"Timeline request received | limit={args.limit}")
    elif args.list_sessions:
        log.phase(f"Session archive request received | limit={args.limit}")
    elif args.session_mode and args.session_id is None and args.delete_id is None:
        log.phase(f"Session archive request received via --session | limit={args.limit}")
    elif args.session_id is not None:
        log.phase(f"Session detail request received | id={args.session_id}")
    elif args.delete_id is not None:
        scope = "all sessions" if args.delete_id == -1 else f"session id={args.delete_id}"
        log.phase(f"Session deletion request received | {scope}")
    else:
        ports_label = args.ports or (f"top-{args.top_ports}" if args.top_ports else "default")
        log.phase(f"Target locked: {args.target} | save={args.save_mode} | ports={ports_label}")
    if args.dev_mode or args.check_only:
        run_preflight()

    if args.check_only:
        log.success(f"Check run complete in {_format_duration(time.monotonic() - app_started_at)}")
        return 0

    if (
        args.diff_ids is not None
        or args.diff_global
        or args.devices_mode
        or args.device_query is not None
        or args.timeline_mode
        or args.list_sessions
        or args.session_mode
        or args.session_id is not None
        or args.delete_id is not None
    ):
        from src.db import create_session_factory, init_db
        from src.history import (
            compare_sessions,
            copy_to_clipboard,
            delete_sessions,
            format_device_analytics,
            format_global_dynamics,
            format_session_summaries,
            format_timeline,
            get_session_detail,
            list_sessions,
            render_device_report,
            render_session_detail,
            summarize_device_analytics,
            summarize_global_dynamics,
            summarize_timeline,
        )

        log.phase("Reading saved scan sessions")
        init_db(db_path=args.db_path)
        session_factory = create_session_factory(db_path=args.db_path)
        with session_factory() as session:
            if args.diff_ids is not None:
                report = compare_sessions(
                    session,
                    args.diff_ids[0],
                    args.diff_ids[1],
                    out_format=args.out_format,
                )
                _emit_report(
                    report=report,
                    out_format=args.out_format,
                    out_path=args.out_path,
                    action_label="Session diff",
                    started_at=app_started_at,
                    clipboard_func=copy_to_clipboard,
                )
                return 0
            if args.diff_global:
                report = format_global_dynamics(
                    summarize_global_dynamics(
                        session,
                        args.limit,
                        status_filter=args.status_filter,
                        target_filter=args.target_filter,
                    ),
                    out_format=args.out_format,
                )
                _emit_report(
                    report=report,
                    out_format=args.out_format,
                    out_path=args.out_path,
                    action_label="Global dynamics",
                    started_at=app_started_at,
                    clipboard_func=copy_to_clipboard,
                )
                return 0
            if args.devices_mode:
                report = format_device_analytics(
                    summarize_device_analytics(
                        session,
                        args.limit,
                        status_filter=args.status_filter,
                        target_filter=args.target_filter,
                        vendor_filter=args.vendor_filter,
                        mac_only=args.mac_only,
                        ip_only=args.ip_only,
                    ),
                    out_format=args.out_format,
                )
                _emit_report(
                    report=report,
                    out_format=args.out_format,
                    out_path=args.out_path,
                    action_label="Device analytics",
                    started_at=app_started_at,
                    clipboard_func=copy_to_clipboard,
                )
                return 0
            if args.device_query is not None:
                report = render_device_report(
                    session=session,
                    query=args.device_query,
                    limit=args.limit,
                    out_format=args.out_format,
                    vendor_filter=args.vendor_filter,
                    mac_only=args.mac_only,
                    ip_only=args.ip_only,
                    status_filter=args.status_filter,
                    target_filter=args.target_filter,
                )
                _emit_report(
                    report=report,
                    out_format=args.out_format,
                    out_path=args.out_path,
                    action_label="Device history",
                    started_at=app_started_at,
                    clipboard_func=copy_to_clipboard,
                )
                return 0
            if args.timeline_mode:
                report = format_timeline(
                    summarize_timeline(
                        session,
                        args.limit,
                        status_filter=args.status_filter,
                        target_filter=args.target_filter,
                    ),
                    out_format=args.out_format,
                )
                _emit_report(
                    report=report,
                    out_format=args.out_format,
                    out_path=args.out_path,
                    action_label="Timeline",
                    started_at=app_started_at,
                    clipboard_func=copy_to_clipboard,
                )
                return 0
            if args.delete_id is not None:
                if not _confirm_deletion(args.delete_id):
                    log.warn("Deletion aborted")
                    return 1
                deleted_count = delete_sessions(session, args.delete_id)
                message = (
                    "History wipe complete"
                    if args.delete_id == -1
                    else f"Session #{args.delete_id} deleted"
                )
                log.success(
                    f"{message} ({deleted_count} session(s) removed) "
                    f"in {_format_duration(time.monotonic() - app_started_at)}"
                )
                return 0
            if args.session_id is not None:
                detail = get_session_detail(session, args.session_id, host_query=args.host_query)
                rendered = render_session_detail(detail, args.out_format)
                _emit_report(
                    report=rendered,
                    out_format=args.out_format,
                    out_path=args.out_path,
                    action_label="Session report",
                    started_at=app_started_at,
                    clipboard_func=copy_to_clipboard,
                )
                return 0
            summaries = list_sessions(
                session,
                args.limit,
                status_filter=args.status_filter,
                target_filter=args.target_filter,
            )
        print(format_session_summaries(summaries))
        log.success(
            f"Session listing complete in {_format_duration(time.monotonic() - app_started_at)}"
        )
        return 0

    if args.save_mode == "xml":
        log.phase("Running in XML-only mode")
        result = run_scan(args)
        log.success(
            f"{summarize_scan(result)} "
            f"app_total={_format_duration(time.monotonic() - app_started_at)}"
        )
        return 0

    from src.db import create_session_factory, init_db
    from src.persistence import complete_scan_session, fail_scan_session, start_scan_session

    log.phase("Running in database mode")
    init_db(db_path=args.db_path)
    session_factory = create_session_factory(db_path=args.db_path)
    log.success("Database schema is ready")

    with session_factory() as session:
        started_at = datetime.now()
        scan_session = start_scan_session(session, args, started_at)
        try:
            result = run_scan(args)
            complete_scan_session(
                session=session,
                scan_session=scan_session,
                options=args,
                result=result,
                finished_at=datetime.now(),
            )
        except Exception as exc:
            fail_scan_session(
                session=session,
                scan_session=scan_session,
                error=exc,
                finished_at=datetime.now(),
            )
            raise

    log.success(
        f"{summarize_scan(result)} "
        f"app_total={_format_duration(time.monotonic() - app_started_at)}"
    )
    return 0


def _format_duration(seconds: float) -> str:
    total_seconds = max(0, int(round(seconds)))
    minutes, secs = divmod(total_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def _emit_report(
    report: str,
    out_format: str,
    out_path,
    action_label: str,
    started_at: float,
    clipboard_func,
) -> None:
    if out_path is not None:
        resolved_path = out_path.expanduser().resolve()
        resolved_path.parent.mkdir(parents=True, exist_ok=True)
        resolved_path.write_text(report, encoding="utf-8")
        log.success(
            f"{action_label} written to {resolved_path} "
            f"in {_format_duration(time.monotonic() - started_at)}"
        )
        return
    if out_format == "clipboard":
        print(report)
        clipboard_func(report)
        log.success(
            f"{action_label} copied to clipboard in "
            f"{_format_duration(time.monotonic() - started_at)}"
        )
        return
    print(report)
    log.success(
        f"{action_label} complete in {_format_duration(time.monotonic() - started_at)}"
    )


def _confirm_deletion(delete_id: int) -> bool:
    if not sys.stdin.isatty():
        raise RuntimeError("interactive confirmation requires a TTY")
    prompt = (
        "Delete every saved session from history? Type 'y' to continue: "
        if delete_id == -1
        else f"Delete session #{delete_id}? Type 'y' to continue: "
    )
    return input(prompt).strip().lower() == "y"


if __name__ == "__main__":
    raise SystemExit(main())

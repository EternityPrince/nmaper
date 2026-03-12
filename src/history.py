from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from dataclasses import asdict, dataclass

from sqlalchemy import delete, desc, func, select
from sqlalchemy.orm import Session, selectinload

from src.fuzzy import fuzzy_match
from src.models import (
    Device,
    DeviceIPAddress,
    HostObservation,
    Network,
    OSMatch,
    Port,
    ScanSession,
    Script,
    ScriptResult,
    ServiceObservation,
    SessionNetwork,
    Trace,
    TraceHop,
)


@dataclass(slots=True)
class SessionSummary:
    session_id: int
    started_at: object
    finished_at: object | None
    duration_seconds: float | None
    status: str
    target_input: str
    nmap_version: str | None
    discovered_hosts: int | None
    live_hosts: int | None


@dataclass(slots=True)
class SessionDetail:
    session: ScanSession
    session_network: SessionNetwork | None
    host_observations: list[HostObservation]


@dataclass(slots=True)
class GlobalDynamics:
    session_ids: list[int]
    unique_hosts: int
    stable_hosts: list[str]
    transient_hosts: list[str]
    recurring_hosts: list[tuple[str, int]]
    volatile_hosts: list[tuple[str, int]]
    common_ports: list[tuple[str, int]]
    latest_summary: str | None


@dataclass(slots=True)
class DeviceAnalytics:
    session_ids: list[int]
    unique_devices: int
    mac_backed_devices: int
    ip_only_devices: int
    recurring_devices: list[tuple[str, int]]
    vendor_leaders: list[tuple[str, int]]
    multi_ip_devices: list[tuple[str, int]]


@dataclass(slots=True)
class TimelineEntry:
    from_session_id: int
    to_session_id: int
    from_started_at: object
    to_started_at: object
    new_hosts: list[str]
    disappeared_hosts: list[str]
    changed_hosts: list[str]


@dataclass(slots=True)
class TimelineSummary:
    session_ids: list[int]
    entries: list[TimelineEntry]


@dataclass(slots=True)
class DeviceHistoryEntry:
    session_id: int
    started_at: object
    target_input: str
    ip_address: str | None
    status: str
    ports: list[str]
    top_os: str | None


@dataclass(slots=True)
class DeviceReport:
    query: str
    device_key: str
    mac_address: str | None
    vendor: str | None
    ip_addresses: list[str]
    first_seen_session_id: int | None
    last_seen_session_id: int | None
    session_count: int
    sessions: list[DeviceHistoryEntry]


@dataclass(slots=True)
class DeviceSearchResult:
    query: str
    matches: list[DeviceReport]


def list_sessions(
    session: Session,
    limit: int,
    status_filter: str | None = None,
    target_filter: str | None = None,
) -> list[SessionSummary]:
    rows = session.execute(
        select(ScanSession, SessionNetwork)
        .outerjoin(SessionNetwork, SessionNetwork.session_id == ScanSession.id)
        .order_by(desc(ScanSession.started_at))
    ).all()

    summaries: list[SessionSummary] = []
    for scan_session, session_network in rows:
        summaries.append(
            SessionSummary(
                session_id=scan_session.id,
                started_at=scan_session.started_at,
                finished_at=scan_session.finished_at,
                duration_seconds=scan_session.duration_seconds,
                status=scan_session.status,
                target_input=scan_session.target_input,
                nmap_version=scan_session.nmap_version,
                discovered_hosts=session_network.discovered_host_count
                if session_network is not None
                else None,
                live_hosts=session_network.live_host_count if session_network is not None else None,
            )
        )
    filtered = [
        summary
        for summary in summaries
        if (status_filter is None or summary.status == status_filter)
        and (target_filter is None or fuzzy_match(target_filter, summary.target_input))
    ]
    return filtered[:limit]


def format_session_summaries(summaries: list[SessionSummary]) -> str:
    if not summaries:
        return "No saved sessions found."

    lines = []
    for summary in summaries:
        duration = _format_duration(summary.duration_seconds)
        discovered = summary.discovered_hosts if summary.discovered_hosts is not None else "?"
        live = summary.live_hosts if summary.live_hosts is not None else "?"
        version = summary.nmap_version or "unknown"
        lines.append(
            f"#{summary.session_id} {summary.status:<9} "
            f"{summary.started_at:%Y-%m-%d %H:%M:%S} "
            f"target={summary.target_input} "
            f"duration={duration} "
            f"hosts={live}/{discovered} "
            f"nmap={version}"
        )
    return "\n".join(lines)


def compare_sessions(
    session: Session,
    left_id: int,
    right_id: int,
    out_format: str = "clipboard",
) -> str:
    left = get_session_detail(session, left_id)
    right = get_session_detail(session, right_id)
    if left is None or right is None:
        missing = []
        if left is None:
            missing.append(str(left_id))
        if right is None:
            missing.append(str(right_id))
        return f"Session not found: {', '.join(missing)}"

    left_map = _host_snapshot_map(left)
    right_map = _host_snapshot_map(right)
    left_hosts = set(left_map)
    right_hosts = set(right_map)

    new_hosts = sorted(right_hosts - left_hosts)
    disappeared_hosts = sorted(left_hosts - right_hosts)
    changed_hosts: list[str] = []
    for host in sorted(left_hosts & right_hosts):
        changes = _diff_host_snapshot(left_map[host], right_map[host])
        if changes:
            changed_hosts.append(f"{host}: {', '.join(changes)}")

    diff_payload = {
        "left": {
            "session_id": left_id,
            "started_at": left.session.started_at.isoformat(sep=" "),
            "target": left.session.target_input,
        },
        "right": {
            "session_id": right_id,
            "started_at": right.session.started_at.isoformat(sep=" "),
            "target": right.session.target_input,
        },
        "new_hosts": new_hosts,
        "disappeared_hosts": disappeared_hosts,
        "changed_hosts": changed_hosts,
    }
    if out_format == "json":
        return _json_dumps(diff_payload)
    if out_format == "md":
        return _render_session_diff_markdown(diff_payload)
    return _render_session_diff_terminal(diff_payload)


def summarize_global_dynamics(
    session: Session,
    limit: int,
    status_filter: str | None = None,
    target_filter: str | None = None,
) -> GlobalDynamics:
    summaries = list_sessions(
        session,
        limit,
        status_filter=status_filter,
        target_filter=target_filter,
    )
    if not summaries:
        return GlobalDynamics([], 0, [], [], [], [], [], None)

    details = [
        detail
        for summary in summaries
        if (detail := get_session_detail(session, summary.session_id)) is not None
    ]
    host_presence: Counter[str] = Counter()
    host_port_signatures: dict[str, set[tuple[str, ...]]] = {}
    port_frequency: Counter[str] = Counter()

    for detail in details:
        snapshot = _host_snapshot_map(detail)
        for ip_address, host_data in snapshot.items():
            host_presence[ip_address] += 1
            signature = tuple(sorted(host_data["ports"]))
            host_port_signatures.setdefault(ip_address, set()).add(signature)
            for port in host_data["ports"]:
                port_frequency[port] += 1

    total_sessions = len(details)
    stable_hosts = sorted([host for host, seen in host_presence.items() if seen == total_sessions])
    transient_hosts = sorted([host for host, seen in host_presence.items() if seen == 1])
    recurring_hosts = host_presence.most_common(5)
    volatile_hosts = sorted(
        (
            (host, len(signatures))
            for host, signatures in host_port_signatures.items()
            if len(signatures) > 1
        ),
        key=lambda item: item[1],
        reverse=True,
    )[:5]
    common_ports = port_frequency.most_common(8)

    latest_summary = None
    if len(details) >= 2:
        latest_summary = _one_line_diff(
            _host_snapshot_map(details[1]),
            _host_snapshot_map(details[0]),
            details[1].session.id,
            details[0].session.id,
        )

    return GlobalDynamics(
        session_ids=[detail.session.id for detail in details],
        unique_hosts=len(host_presence),
        stable_hosts=stable_hosts,
        transient_hosts=transient_hosts,
        recurring_hosts=recurring_hosts,
        volatile_hosts=volatile_hosts,
        common_ports=common_ports,
        latest_summary=latest_summary,
    )


def format_global_dynamics(dynamics: GlobalDynamics, out_format: str = "clipboard") -> str:
    if not dynamics.session_ids:
        return "No saved sessions found."

    if out_format == "json":
        return _json_dumps(asdict(dynamics))
    if out_format == "md":
        return _render_global_dynamics_markdown(dynamics)

    lines = [
        _color("=" * 72, "cyan"),
        _color("Global Dynamics", "cyan"),
        _color("-" * 72, "cyan"),
        f"Sessions analyzed : {', '.join(str(session_id) for session_id in dynamics.session_ids)}",
        f"Unique hosts      : {dynamics.unique_hosts}",
        f"Stable hosts      : {len(dynamics.stable_hosts)}",
        f"Transient hosts   : {len(dynamics.transient_hosts)}",
    ]
    if dynamics.latest_summary:
        lines.extend(["", _color("Latest Movement", "yellow"), f"  {dynamics.latest_summary}"])
    if dynamics.recurring_hosts:
        lines.extend(["", _color("Most Recurring Hosts", "green")])
        lines.extend(
            f"  {host} seen in {count} sessions" for host, count in dynamics.recurring_hosts
        )
    if dynamics.volatile_hosts:
        lines.extend(["", _color("Most Volatile Hosts", "yellow")])
        lines.extend(
            f"  {host} changed port signature {count} times"
            for host, count in dynamics.volatile_hosts
        )
    if dynamics.common_ports:
        lines.extend(["", _color("Most Common Open Ports", "cyan")])
        lines.extend(f"  {port} observed {count} times" for port, count in dynamics.common_ports)
    if dynamics.transient_hosts:
        lines.extend(
            ["", _color("Transient Hosts", "red")]
            + [f"  {host}" for host in dynamics.transient_hosts[:10]]
        )
    lines.append(_color("=" * 72, "cyan"))
    return "\n".join(lines)


def summarize_device_analytics(
    session: Session,
    limit: int,
    status_filter: str | None = None,
    target_filter: str | None = None,
    vendor_filter: str | None = None,
    mac_only: bool = False,
    ip_only: bool = False,
) -> DeviceAnalytics:
    summaries = list_sessions(
        session,
        limit,
        status_filter=status_filter,
        target_filter=target_filter,
    )
    if not summaries:
        return DeviceAnalytics([], 0, 0, 0, [], [], [])

    details = [
        detail
        for summary in summaries
        if (detail := get_session_detail(session, summary.session_id)) is not None
    ]
    presence: Counter[str] = Counter()
    vendor_counts: Counter[str] = Counter()
    ips_by_device: dict[str, set[str]] = {}
    mac_backed = 0
    ip_only_count = 0
    classified: set[str] = set()

    for detail in details:
        seen_in_session: set[str] = set()
        for host in detail.host_observations:
            ip_address = (
                host.ip_address.ip_address if host.ip_address is not None else "unknown-ip"
            )
            mac_address = (
                host.device.mac_address if host.device and host.device.mac_address else None
            )
            device_key = mac_address or f"ip:{ip_address}"
            vendor = host.device.vendor if host.device and host.device.vendor else "unknown-vendor"
            if vendor_filter and not fuzzy_match(vendor_filter, vendor):
                continue
            if mac_only and not mac_address:
                continue
            if ip_only and mac_address:
                continue
            if device_key not in classified:
                if mac_address:
                    mac_backed += 1
                else:
                    ip_only_count += 1
                classified.add(device_key)
            seen_in_session.add(device_key)
            ips_by_device.setdefault(device_key, set()).add(ip_address)
            vendor_counts[vendor] += 1
        for device_key in seen_in_session:
            presence[device_key] += 1

    recurring_devices = presence.most_common(8)
    vendor_leaders = vendor_counts.most_common(8)
    multi_ip_devices = sorted(
        (
            (device_key, len(ip_addresses))
            for device_key, ip_addresses in ips_by_device.items()
            if len(ip_addresses) > 1
        ),
        key=lambda item: item[1],
        reverse=True,
    )[:8]

    return DeviceAnalytics(
        session_ids=[detail.session.id for detail in details],
        unique_devices=len(classified),
        mac_backed_devices=mac_backed,
        ip_only_devices=ip_only_count,
        recurring_devices=recurring_devices,
        vendor_leaders=vendor_leaders,
        multi_ip_devices=multi_ip_devices,
    )


def format_device_analytics(analytics: DeviceAnalytics, out_format: str = "clipboard") -> str:
    if not analytics.session_ids:
        return "No saved sessions found."

    if out_format == "json":
        return _json_dumps(asdict(analytics))
    if out_format == "md":
        return _render_device_analytics_markdown(analytics)

    lines = [
        _color("=" * 72, "cyan"),
        _color("Device Analytics", "cyan"),
        _color("-" * 72, "cyan"),
        f"Sessions analyzed : {', '.join(str(session_id) for session_id in analytics.session_ids)}",
        f"Unique devices    : {analytics.unique_devices}",
        f"MAC-backed        : {analytics.mac_backed_devices}",
        f"IP-only           : {analytics.ip_only_devices}",
    ]
    if analytics.recurring_devices:
        lines.extend(["", _color("Most Frequent Devices", "green")])
        lines.extend(
            f"  {_format_device_key(device_key)} seen in {count} sessions"
            for device_key, count in analytics.recurring_devices
        )
    if analytics.vendor_leaders:
        lines.extend(["", _color("Top Vendors", "cyan")])
        lines.extend(
            f"  {vendor} observed {count} times" for vendor, count in analytics.vendor_leaders
        )
    if analytics.multi_ip_devices:
        lines.extend(["", _color("Devices With Multiple IPs", "yellow")])
        lines.extend(
            f"  {_format_device_key(device_key)} used {count} IPs"
            for device_key, count in analytics.multi_ip_devices
        )
    lines.append(_color("=" * 72, "cyan"))
    return "\n".join(lines)


def summarize_timeline(
    session: Session,
    limit: int,
    status_filter: str | None = None,
    target_filter: str | None = None,
) -> TimelineSummary:
    summaries = list(
        reversed(
            list_sessions(
                session,
                limit,
                status_filter=status_filter,
                target_filter=target_filter,
            )
        )
    )
    if len(summaries) < 2:
        return TimelineSummary([summary.session_id for summary in summaries], [])

    details = {
        summary.session_id: get_session_detail(session, summary.session_id)
        for summary in summaries
    }
    entries: list[TimelineEntry] = []
    for previous, current in zip(summaries, summaries[1:], strict=False):
        previous_detail = details.get(previous.session_id)
        current_detail = details.get(current.session_id)
        if previous_detail is None or current_detail is None:
            continue
        previous_map = _host_snapshot_map(previous_detail)
        current_map = _host_snapshot_map(current_detail)
        previous_hosts = set(previous_map)
        current_hosts = set(current_map)
        changed_hosts = [
            host
            for host in sorted(previous_hosts & current_hosts)
            if _diff_host_snapshot(previous_map[host], current_map[host])
        ]
        entries.append(
            TimelineEntry(
                from_session_id=previous.session_id,
                to_session_id=current.session_id,
                from_started_at=previous.started_at,
                to_started_at=current.started_at,
                new_hosts=sorted(current_hosts - previous_hosts),
                disappeared_hosts=sorted(previous_hosts - current_hosts),
                changed_hosts=changed_hosts,
            )
        )
    return TimelineSummary([summary.session_id for summary in summaries], entries)


def format_timeline(timeline: TimelineSummary, out_format: str = "clipboard") -> str:
    if not timeline.session_ids:
        return "No saved sessions found."
    if out_format == "json":
        return _json_dumps(asdict(timeline))
    if out_format == "md":
        return _render_timeline_markdown(timeline)

    lines = [
        _color("=" * 72, "cyan"),
        _color("Change Timeline", "cyan"),
        _color("-" * 72, "cyan"),
        f"Sessions analyzed : {', '.join(str(session_id) for session_id in timeline.session_ids)}",
    ]
    if not timeline.entries:
        lines.append("Not enough sessions to build a timeline.")
    else:
        for entry in timeline.entries:
            lines.extend(
                [
                    "",
                    f"{entry.from_session_id} -> {entry.to_session_id}  "
                    f"({_render_timestamp(entry.from_started_at)} "
                    f"-> {_render_timestamp(entry.to_started_at)})",
                    f"  new         : {len(entry.new_hosts)}",
                    f"  disappeared : {len(entry.disappeared_hosts)}",
                    f"  changed     : {len(entry.changed_hosts)}",
                ]
            )
            if entry.new_hosts:
                lines.append(f"  + {' | '.join(entry.new_hosts[:6])}")
            if entry.disappeared_hosts:
                lines.append(f"  - {' | '.join(entry.disappeared_hosts[:6])}")
            if entry.changed_hosts:
                lines.append(f"  * {' | '.join(entry.changed_hosts[:6])}")
    lines.append(_color("=" * 72, "cyan"))
    return "\n".join(lines)


def render_device_report(
    session: Session,
    query: str,
    limit: int,
    out_format: str = "clipboard",
    vendor_filter: str | None = None,
    mac_only: bool = False,
    ip_only: bool = False,
    status_filter: str | None = None,
    target_filter: str | None = None,
) -> str:
    search = search_devices(
        session=session,
        query=query,
        limit=limit,
        vendor_filter=vendor_filter,
        mac_only=mac_only,
        ip_only=ip_only,
        status_filter=status_filter,
        target_filter=target_filter,
    )
    if out_format == "json":
        return _json_dumps(asdict(search))
    if out_format == "md":
        return _render_device_search_markdown(search)
    return _render_device_search_terminal(search)


def search_devices(
    session: Session,
    query: str,
    limit: int,
    vendor_filter: str | None = None,
    mac_only: bool = False,
    ip_only: bool = False,
    status_filter: str | None = None,
    target_filter: str | None = None,
) -> DeviceSearchResult:
    summaries = list_sessions(
        session,
        limit,
        status_filter=status_filter,
        target_filter=target_filter,
    )
    details = [
        detail
        for summary in summaries
        if (detail := get_session_detail(session, summary.session_id)) is not None
    ]
    device_reports: dict[str, DeviceReport] = {}
    for detail in details:
        for host in detail.host_observations:
            device_key = _device_key_for_host(host)
            mac_address = host.device.mac_address if host.device else None
            vendor = host.device.vendor if host.device and host.device.vendor else "unknown-vendor"
            if vendor_filter and not fuzzy_match(vendor_filter, vendor):
                continue
            if mac_only and mac_address is None:
                continue
            if ip_only and mac_address is not None:
                continue
            if not fuzzy_match(
                query,
                device_key,
                mac_address or "",
                vendor,
                host.ip_address.ip_address if host.ip_address else "",
            ):
                continue
            report = device_reports.get(device_key)
            if report is None:
                report = DeviceReport(
                    query=query,
                    device_key=device_key,
                    mac_address=mac_address,
                    vendor=vendor,
                    ip_addresses=[],
                    first_seen_session_id=(
                        host.device.first_seen_session_id if host.device else None
                    ),
                    last_seen_session_id=host.device.last_seen_session_id if host.device else None,
                    session_count=0,
                    sessions=[],
                )
                device_reports[device_key] = report
            ip_address = host.ip_address.ip_address if host.ip_address else None
            if ip_address and ip_address not in report.ip_addresses:
                report.ip_addresses.append(ip_address)
            report.session_count += 1
            report.sessions.append(
                DeviceHistoryEntry(
                    session_id=detail.session.id,
                    started_at=detail.session.started_at,
                    target_input=detail.session.target_input,
                    ip_address=ip_address,
                    status=host.status,
                    ports=sorted(
                        f"{service.port.port_number}/{service.port.protocol}"
                        for service in host.service_observations
                        if service.port is not None
                    ),
                    top_os=_top_os_name(host),
                )
            )
    matches = sorted(
        device_reports.values(),
        key=lambda item: (item.session_count, item.device_key),
        reverse=True,
    )
    return DeviceSearchResult(query=query, matches=matches)


def get_session_detail(
    session: Session,
    session_id: int,
    host_query: str | None = None,
) -> SessionDetail | None:
    scan_session = session.scalar(
        select(ScanSession)
        .where(ScanSession.id == session_id)
        .options(
            selectinload(ScanSession.session_networks),
            selectinload(ScanSession.host_observations).selectinload(HostObservation.device),
            selectinload(ScanSession.host_observations).selectinload(HostObservation.ip_address),
            selectinload(ScanSession.host_observations).selectinload(HostObservation.os_matches),
            selectinload(ScanSession.host_observations)
            .selectinload(HostObservation.service_observations)
            .selectinload(ServiceObservation.port),
            selectinload(ScanSession.host_observations)
            .selectinload(HostObservation.trace)
            .selectinload(Trace.hops),
        )
    )
    if scan_session is None:
        return None
    session_network = scan_session.session_networks[0] if scan_session.session_networks else None
    hosts = sorted(
        scan_session.host_observations,
        key=lambda item: item.ip_address.ip_address if item.ip_address is not None else "",
    )
    if host_query:
        hosts = [host for host in hosts if _match_host_query(host, host_query)]
    return SessionDetail(
        session=scan_session,
        session_network=session_network,
        host_observations=hosts,
    )


def render_session_detail(detail: SessionDetail | None, out_format: str) -> str:
    if out_format == "json":
        return format_session_detail_json(detail)
    if out_format == "md":
        return format_session_detail_markdown(detail)
    return format_session_detail_terminal(detail)


def format_session_detail_terminal(detail: SessionDetail | None) -> str:
    if detail is None:
        return "Session not found."

    session = detail.session
    lines = [
        _color("=" * 72, "cyan"),
        f"{_color('Session Report', 'cyan')} #{session.id} {_status_label(session.status)}",
        _color("-" * 72, "cyan"),
        f"Started   : {session.started_at:%Y-%m-%d %H:%M:%S}",
        f"Finished  : {session.finished_at:%Y-%m-%d %H:%M:%S}"
        if session.finished_at
        else "Finished  : running",
        f"Duration  : {_format_duration(session.duration_seconds)}",
        f"Target    : {session.target_input}",
        f"Nmap      : {session.nmap_version or 'unknown'}",
    ]
    if detail.session_network is not None:
        live_hosts = detail.session_network.live_host_count or 0
        discovered_hosts = detail.session_network.discovered_host_count or 0
        lines.append(
            f"Hosts     : {live_hosts}/{discovered_hosts} live"
        )
    notes = _parse_notes(session.notes)
    detail_errors = notes.get("detail_errors")
    if isinstance(detail_errors, dict):
        lines.append(f"Errors    : {len(detail_errors)} detailed scan failure(s)")

    if detail.host_observations:
        lines.append("")
        lines.append(_color("Host Findings", "cyan"))
        lines.append(_color("-" * 72, "cyan"))
        for host in detail.host_observations:
            ip_address = host.ip_address.ip_address if host.ip_address is not None else "unknown"
            mac = (
                host.device.mac_address
                if host.device is not None and host.device.mac_address
                else "no-mac"
            )
            vendor = (
                host.device.vendor
                if host.device is not None and host.device.vendor
                else "unknown-vendor"
            )
            hostnames = _decode_json_list(host.hostnames_json)
            hostname_text = f" [{', '.join(hostnames)}]" if hostnames else ""
            lines.append(
                f"[{_status_label(host.status)}] {_color(ip_address, 'green')}  "
                f"{mac}  {vendor}{hostname_text}"
            )
            if host.os_matches:
                os_line = ", ".join(
                    f"{match.name} ({match.accuracy or '?'}%)"
                    for match in sorted(
                        host.os_matches, key=lambda item: item.accuracy or 0, reverse=True
                    )[:2]
                )
                lines.append(f"  os    : {os_line}")
            services = sorted(
                host.service_observations,
                key=lambda item: (
                    item.port.port_number if item.port is not None else 0,
                    item.port.protocol if item.port is not None else "",
                ),
            )
            if services:
                service_parts = []
                for service in services:
                    port = service.port.port_number if service.port is not None else "?"
                    protocol = service.port.protocol if service.port is not None else "?"
                    name = service.service_name or "unknown"
                    version_parts = [
                        part for part in [service.product, service.version] if part
                    ]
                    version = f" ({' '.join(version_parts)})" if version_parts else ""
                    service_parts.append(f"{port}/{protocol} {name}{version}")
                lines.append(f"  ports : {' | '.join(service_parts)}")
            if host.trace is not None and host.trace.hops:
                hop_line = " -> ".join(
                    hop.ip_address or hop.hostname or f"hop-{hop.hop_index}"
                    for hop in sorted(host.trace.hops, key=lambda item: item.hop_index)
                )
                lines.append(f"  trace : {hop_line}")
            lines.append("")
    lines.append(_color("=" * 72, "cyan"))
    return "\n".join(lines)


def format_session_detail_markdown(detail: SessionDetail | None) -> str:
    if detail is None:
        return "# Session not found\n"

    session = detail.session
    notes = _parse_notes(session.notes)
    detail_errors = notes.get("detail_errors")
    lines = [
        f"# Session {session.id}",
        "",
        f"- Status: `{session.status}`",
        f"- Started: `{session.started_at:%Y-%m-%d %H:%M:%S}`",
        (
            f"- Finished: `{session.finished_at:%Y-%m-%d %H:%M:%S}`"
            if session.finished_at
            else "- Finished: `running`"
        ),
        f"- Duration: `{_format_duration(session.duration_seconds)}`",
        f"- Target: `{session.target_input}`",
        f"- Nmap: `{session.nmap_version or 'unknown'}`",
    ]
    if detail.session_network is not None:
        live_hosts = detail.session_network.live_host_count or 0
        discovered_hosts = detail.session_network.discovered_host_count or 0
        lines.append(
            f"- Hosts: `{live_hosts}/{discovered_hosts} live`"
        )
    if isinstance(detail_errors, dict):
        lines.append(f"- Detailed scan errors: `{len(detail_errors)}`")

    if detail.host_observations:
        lines.extend(["", "## Host Findings", ""])
        for host in detail.host_observations:
            ip_address = host.ip_address.ip_address if host.ip_address is not None else "unknown"
            hostnames = _decode_json_list(host.hostnames_json)
            lines.append(f"### {ip_address}")
            lines.append("")
            lines.append(f"- Status: `{host.status}`")
            mac_address = (
                host.device.mac_address if host.device and host.device.mac_address else "no-mac"
            )
            vendor = host.device.vendor if host.device and host.device.vendor else "unknown-vendor"
            lines.append(f"- MAC: `{mac_address}`")
            lines.append(f"- Vendor: `{vendor}`")
            if hostnames:
                lines.append(f"- Hostnames: `{', '.join(hostnames)}`")
            if host.os_matches:
                os_line = ", ".join(
                    f"{match.name} ({match.accuracy or '?'}%)"
                    for match in sorted(
                        host.os_matches, key=lambda item: item.accuracy or 0, reverse=True
                    )[:2]
                )
                lines.append(f"- OS: `{os_line}`")
            if host.service_observations:
                lines.append("- Ports:")
                for service in sorted(
                    host.service_observations,
                    key=lambda item: (
                        item.port.port_number if item.port is not None else 0,
                        item.port.protocol if item.port is not None else "",
                    ),
                ):
                    port = service.port.port_number if service.port is not None else "?"
                    protocol = service.port.protocol if service.port is not None else "?"
                    name = service.service_name or "unknown"
                    version_parts = [part for part in [service.product, service.version] if part]
                    version = f" ({' '.join(version_parts)})" if version_parts else ""
                    lines.append(f"  - `{port}/{protocol}` {name}{version}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def format_session_detail_json(detail: SessionDetail | None) -> str:
    if detail is None:
        return _json_dumps({"error": "Session not found."})

    session = detail.session
    payload = {
        "session": {
            "id": session.id,
            "status": session.status,
            "started_at": session.started_at.isoformat(sep=" "),
            "finished_at": session.finished_at.isoformat(sep=" ") if session.finished_at else None,
            "duration_seconds": session.duration_seconds,
            "target": session.target_input,
            "nmap_version": session.nmap_version,
            "hosts": {
                "live": detail.session_network.live_host_count if detail.session_network else None,
                "discovered": (
                    detail.session_network.discovered_host_count if detail.session_network else None
                ),
            },
            "notes": _parse_notes(session.notes),
        },
        "hosts": [],
    }
    for host in detail.host_observations:
        host_payload = {
            "ip_address": host.ip_address.ip_address if host.ip_address else None,
            "status": host.status,
            "mac_address": host.device.mac_address if host.device else None,
            "vendor": host.device.vendor if host.device else None,
            "hostnames": _decode_json_list(host.hostnames_json),
            "uptime_seconds": host.uptime_seconds,
            "distance_hops": host.distance_hops,
            "os_matches": [
                {"name": match.name, "accuracy": match.accuracy, "line": match.line}
                for match in host.os_matches
            ],
            "services": [
                {
                    "port": service.port.port_number if service.port else None,
                    "protocol": service.port.protocol if service.port else None,
                    "state": service.state,
                    "service_name": service.service_name,
                    "product": service.product,
                    "version": service.version,
                }
                for service in sorted(
                    host.service_observations,
                    key=lambda item: (
                        item.port.port_number if item.port is not None else 0,
                        item.port.protocol if item.port is not None else "",
                    ),
                )
            ],
            "trace": [
                {
                    "hop_index": hop.hop_index,
                    "ip_address": hop.ip_address,
                    "hostname": hop.hostname,
                    "rtt": hop.rtt,
                }
                for hop in sorted(host.trace.hops, key=lambda item: item.hop_index)
            ] if host.trace else [],
        }
        payload["hosts"].append(host_payload)
    return _json_dumps(payload)


def copy_to_clipboard(text: str) -> None:
    completed = subprocess.run(
        ["pbcopy"],
        input=text,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "failed to copy report to clipboard")


def delete_sessions(session: Session, delete_id: int) -> int:
    if delete_id == -1:
        count = session.scalar(select(func.count()).select_from(ScanSession)) or 0
        _delete_all_history(session)
        session.commit()
        return count

    scan_session = session.get(ScanSession, delete_id)
    if scan_session is None:
        return 0
    _delete_single_session(session, delete_id)
    session.commit()
    return 1


def _format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "unknown"
    total_seconds = max(0, int(round(seconds)))
    minutes, secs = divmod(total_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def _delete_single_session(session: Session, session_id: int) -> None:
    host_ids = list(
        session.scalars(select(HostObservation.id).where(HostObservation.session_id == session_id))
    )
    service_ids: list[int] = []
    trace_ids: list[int] = []
    if host_ids:
        service_ids = list(
            session.scalars(
                select(ServiceObservation.id).where(
                    ServiceObservation.host_observation_id.in_(host_ids)
                )
            )
        )
        trace_ids = list(
            session.scalars(select(Trace.id).where(Trace.host_observation_id.in_(host_ids)))
        )

    if service_ids:
        session.execute(
            delete(ScriptResult).where(ScriptResult.service_observation_id.in_(service_ids))
        )
    if host_ids:
        session.execute(delete(ScriptResult).where(ScriptResult.host_observation_id.in_(host_ids)))
        session.execute(delete(OSMatch).where(OSMatch.host_observation_id.in_(host_ids)))
    if trace_ids:
        session.execute(delete(TraceHop).where(TraceHop.trace_id.in_(trace_ids)))
        session.execute(delete(Trace).where(Trace.id.in_(trace_ids)))
    if service_ids:
        session.execute(delete(ServiceObservation).where(ServiceObservation.id.in_(service_ids)))
    if host_ids:
        session.execute(delete(HostObservation).where(HostObservation.id.in_(host_ids)))

    session.execute(delete(SessionNetwork).where(SessionNetwork.session_id == session_id))
    session.execute(delete(ScanSession).where(ScanSession.id == session_id))
    _repair_metadata(session)
    _delete_orphans(session)


def _delete_all_history(session: Session) -> None:
    session.execute(delete(ScriptResult))
    session.execute(delete(TraceHop))
    session.execute(delete(Trace))
    session.execute(delete(OSMatch))
    session.execute(delete(ServiceObservation))
    session.execute(delete(HostObservation))
    session.execute(delete(SessionNetwork))
    session.execute(delete(DeviceIPAddress))
    session.execute(delete(Device))
    session.execute(delete(Network))
    session.execute(delete(Port))
    session.execute(delete(Script))
    session.execute(delete(ScanSession))


def _repair_metadata(session: Session) -> None:
    for network in session.scalars(select(Network)).all():
        session_ids = session.scalars(
            select(SessionNetwork.session_id)
            .where(SessionNetwork.network_id == network.id)
            .order_by(SessionNetwork.session_id)
        ).all()
        network.first_seen_session_id = session_ids[0] if session_ids else None
        network.last_seen_session_id = session_ids[-1] if session_ids else None

    for device in session.scalars(select(Device)).all():
        session_ids = session.scalars(
            select(HostObservation.session_id)
            .where(HostObservation.device_id == device.id)
            .order_by(HostObservation.session_id)
        ).all()
        device.first_seen_session_id = session_ids[0] if session_ids else None
        device.last_seen_session_id = session_ids[-1] if session_ids else None

    for ip_record in session.scalars(select(DeviceIPAddress)).all():
        session_ids = session.scalars(
            select(HostObservation.session_id)
            .where(HostObservation.ip_address_id == ip_record.id)
            .order_by(HostObservation.session_id)
        ).all()
        ip_record.first_seen_session_id = session_ids[0] if session_ids else None
        ip_record.last_seen_session_id = session_ids[-1] if session_ids else None


def _delete_orphans(session: Session) -> None:
    referenced_ip_ids = set(
        session.scalars(
            select(HostObservation.ip_address_id).where(HostObservation.ip_address_id.is_not(None))
        ).all()
    )
    for ip_record in session.scalars(select(DeviceIPAddress)).all():
        if ip_record.id not in referenced_ip_ids:
            session.delete(ip_record)

    referenced_device_ids = set(session.scalars(select(DeviceIPAddress.device_id)).all())
    for device in session.scalars(select(Device)).all():
        if device.id not in referenced_device_ids:
            session.delete(device)

    referenced_network_ids = set(session.scalars(select(SessionNetwork.network_id)).all())
    referenced_network_ids.update(
        [
            network_id
            for network_id in session.scalars(
                select(DeviceIPAddress.network_id).where(DeviceIPAddress.network_id.is_not(None))
            ).all()
            if network_id is not None
        ]
    )
    for network in session.scalars(select(Network)).all():
        if network.id not in referenced_network_ids:
            session.delete(network)

    referenced_port_ids = set(session.scalars(select(ServiceObservation.port_id)).all())
    for port in session.scalars(select(Port)).all():
        if port.id not in referenced_port_ids:
            session.delete(port)

    referenced_script_ids = set(session.scalars(select(ScriptResult.script_id)).all())
    for script in session.scalars(select(Script)).all():
        if script.id not in referenced_script_ids:
            session.delete(script)


def _parse_notes(notes: str | None) -> dict[str, object]:
    if not notes:
        return {}
    try:
        return json.loads(notes)
    except json.JSONDecodeError:
        return {"raw": notes}


def _json_dumps(payload: object) -> str:
    return json.dumps(payload, indent=2, default=_json_default)


def _json_default(value: object) -> str:
    if hasattr(value, "isoformat"):
        return value.isoformat(sep=" ")
    raise TypeError(f"Object of type {value.__class__.__name__} is not JSON serializable")


def _decode_json_list(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return []
    return [str(item) for item in decoded] if isinstance(decoded, list) else []


def _color(text: str, color: str) -> str:
    if not sys.stdout.isatty():
        return text
    colors = {
        "reset": "\033[0m",
        "cyan": "\033[36m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "red": "\033[31m",
    }
    return f"{colors[color]}{text}{colors['reset']}"


def _status_label(status: str) -> str:
    color = {
        "completed": "green",
        "running": "yellow",
        "failed": "red",
        "up": "green",
        "down": "red",
        "unknown": "yellow",
    }.get(status, "cyan")
    return _color(status, color)


def _host_snapshot_map(detail: SessionDetail) -> dict[str, dict[str, object]]:
    snapshot: dict[str, dict[str, object]] = {}
    for host in detail.host_observations:
        ip_address = host.ip_address.ip_address if host.ip_address is not None else None
        if ip_address is None:
            continue
        top_os = None
        if host.os_matches:
            top_match = max(host.os_matches, key=lambda item: item.accuracy or 0)
            top_os = top_match.name
        snapshot[ip_address] = {
            "status": host.status,
            "ports": {
                f"{service.port.port_number}/{service.port.protocol}"
                for service in host.service_observations
                if service.port is not None
            },
            "os": top_os,
        }
    return snapshot


def _diff_host_snapshot(left: dict[str, object], right: dict[str, object]) -> list[str]:
    changes: list[str] = []
    left_status = left["status"]
    right_status = right["status"]
    if left_status != right_status:
        changes.append(f"status {left_status}->{right_status}")

    left_ports = set(left["ports"]) if isinstance(left["ports"], set) else set()
    right_ports = set(right["ports"]) if isinstance(right["ports"], set) else set()
    opened = sorted(right_ports - left_ports)
    closed = sorted(left_ports - right_ports)
    if opened:
        changes.append(f"opened {', '.join(opened)}")
    if closed:
        changes.append(f"closed {', '.join(closed)}")

    left_os = left.get("os")
    right_os = right.get("os")
    if left_os != right_os:
        changes.append(f"os {left_os or 'unknown'}->{right_os or 'unknown'}")
    return changes


def _one_line_diff(
    left_map: dict[str, dict[str, object]],
    right_map: dict[str, dict[str, object]],
    left_id: int,
    right_id: int,
) -> str:
    left_hosts = set(left_map)
    right_hosts = set(right_map)
    changed = sum(
        1
        for host in left_hosts & right_hosts
        if _diff_host_snapshot(left_map[host], right_map[host])
    )
    return (
        f"{left_id} -> {right_id}: +{len(right_hosts - left_hosts)} "
        f"-{len(left_hosts - right_hosts)} ~{changed}"
    )


def _format_device_key(device_key: str) -> str:
    if device_key.startswith("ip:"):
        return f"ip-only:{device_key[3:]}"
    return device_key


def _render_session_diff_terminal(diff_payload: dict[str, object]) -> str:
    new_hosts = diff_payload["new_hosts"] if isinstance(diff_payload["new_hosts"], list) else []
    disappeared_hosts = (
        diff_payload["disappeared_hosts"]
        if isinstance(diff_payload["disappeared_hosts"], list)
        else []
    )
    changed_hosts = (
        diff_payload["changed_hosts"] if isinstance(diff_payload["changed_hosts"], list) else []
    )
    left = diff_payload["left"] if isinstance(diff_payload["left"], dict) else {}
    right = diff_payload["right"] if isinstance(diff_payload["right"], dict) else {}
    lines = [
        _color("=" * 72, "cyan"),
        f"{_color('Session Diff', 'cyan')} {left.get('session_id')} -> {right.get('session_id')}",
        _color("-" * 72, "cyan"),
        f"Left  : {left.get('started_at')} ({left.get('target')})",
        f"Right : {right.get('started_at')} ({right.get('target')})",
        f"New hosts        : {len(new_hosts)}",
        f"Disappeared hosts: {len(disappeared_hosts)}",
        f"Changed hosts    : {len(changed_hosts)}",
        "",
    ]
    if new_hosts:
        lines.append(_color("New Hosts", "green"))
        lines.extend(f"  + {host}" for host in new_hosts)
        lines.append("")
    if disappeared_hosts:
        lines.append(_color("Disappeared Hosts", "red"))
        lines.extend(f"  - {host}" for host in disappeared_hosts)
        lines.append("")
    if changed_hosts:
        lines.append(_color("Changed Hosts", "yellow"))
        lines.extend(f"  * {host}" for host in changed_hosts)
        lines.append("")
    if not new_hosts and not disappeared_hosts and not changed_hosts:
        lines.append("No material differences detected.")
    lines.append(_color("=" * 72, "cyan"))
    return "\n".join(lines)


def _render_session_diff_markdown(diff_payload: dict[str, object]) -> str:
    new_hosts = diff_payload["new_hosts"] if isinstance(diff_payload["new_hosts"], list) else []
    disappeared_hosts = (
        diff_payload["disappeared_hosts"]
        if isinstance(diff_payload["disappeared_hosts"], list)
        else []
    )
    changed_hosts = (
        diff_payload["changed_hosts"] if isinstance(diff_payload["changed_hosts"], list) else []
    )
    left = diff_payload["left"] if isinstance(diff_payload["left"], dict) else {}
    right = diff_payload["right"] if isinstance(diff_payload["right"], dict) else {}
    lines = [
        f"# Session Diff {left.get('session_id')} -> {right.get('session_id')}",
        "",
        f"- Left: `{left.get('started_at')}` `{left.get('target')}`",
        f"- Right: `{right.get('started_at')}` `{right.get('target')}`",
        f"- New hosts: `{len(new_hosts)}`",
        f"- Disappeared hosts: `{len(disappeared_hosts)}`",
        f"- Changed hosts: `{len(changed_hosts)}`",
    ]
    if new_hosts:
        lines.extend(["", "## New Hosts", ""] + [f"- `{host}`" for host in new_hosts])
    if disappeared_hosts:
        lines.extend(
            ["", "## Disappeared Hosts", ""] + [f"- `{host}`" for host in disappeared_hosts]
        )
    if changed_hosts:
        lines.extend(["", "## Changed Hosts", ""] + [f"- `{host}`" for host in changed_hosts])
    return "\n".join(lines).rstrip() + "\n"


def _render_global_dynamics_markdown(dynamics: GlobalDynamics) -> str:
    lines = [
        "# Global Dynamics",
        "",
        f"- Sessions analyzed: `{', '.join(str(item) for item in dynamics.session_ids)}`",
        f"- Unique hosts: `{dynamics.unique_hosts}`",
        f"- Stable hosts: `{len(dynamics.stable_hosts)}`",
        f"- Transient hosts: `{len(dynamics.transient_hosts)}`",
    ]
    if dynamics.latest_summary:
        lines.append(f"- Latest movement: `{dynamics.latest_summary}`")
    if dynamics.recurring_hosts:
        lines.extend(["", "## Most Recurring Hosts", ""])
        lines.extend(
            f"- `{host}` in `{count}` sessions" for host, count in dynamics.recurring_hosts
        )
    if dynamics.volatile_hosts:
        lines.extend(["", "## Most Volatile Hosts", ""])
        lines.extend(
            f"- `{host}` changed signature `{count}` times"
            for host, count in dynamics.volatile_hosts
        )
    if dynamics.common_ports:
        lines.extend(["", "## Most Common Open Ports", ""])
        lines.extend(
            f"- `{port}` observed `{count}` times" for port, count in dynamics.common_ports
        )
    return "\n".join(lines).rstrip() + "\n"


def _render_device_analytics_markdown(analytics: DeviceAnalytics) -> str:
    lines = [
        "# Device Analytics",
        "",
        f"- Sessions analyzed: `{', '.join(str(item) for item in analytics.session_ids)}`",
        f"- Unique devices: `{analytics.unique_devices}`",
        f"- MAC-backed: `{analytics.mac_backed_devices}`",
        f"- IP-only: `{analytics.ip_only_devices}`",
    ]
    if analytics.recurring_devices:
        lines.extend(["", "## Most Frequent Devices", ""])
        lines.extend(
            f"- `{_format_device_key(device_key)}` in `{count}` sessions"
            for device_key, count in analytics.recurring_devices
        )
    if analytics.vendor_leaders:
        lines.extend(["", "## Top Vendors", ""])
        lines.extend(
            f"- `{vendor}` observed `{count}` times"
            for vendor, count in analytics.vendor_leaders
        )
    if analytics.multi_ip_devices:
        lines.extend(["", "## Devices With Multiple IPs", ""])
        lines.extend(
            f"- `{_format_device_key(device_key)}` used `{count}` IPs"
            for device_key, count in analytics.multi_ip_devices
        )
    return "\n".join(lines).rstrip() + "\n"


def _render_timeline_markdown(timeline: TimelineSummary) -> str:
    lines = [
        "# Change Timeline",
        "",
        f"- Sessions analyzed: `{', '.join(str(item) for item in timeline.session_ids)}`",
    ]
    if not timeline.entries:
        lines.append("- Not enough sessions to build a timeline.")
        return "\n".join(lines).rstrip() + "\n"
    for entry in timeline.entries:
        lines.extend(
            [
                "",
                f"## {entry.from_session_id} -> {entry.to_session_id}",
                "",
                f"- New hosts: `{len(entry.new_hosts)}`",
                f"- Disappeared hosts: `{len(entry.disappeared_hosts)}`",
                f"- Changed hosts: `{len(entry.changed_hosts)}`",
            ]
        )
        if entry.new_hosts:
            lines.extend(["", "### New"] + [f"- `{host}`" for host in entry.new_hosts])
        if entry.disappeared_hosts:
            lines.extend(
                ["", "### Disappeared"] + [f"- `{host}`" for host in entry.disappeared_hosts]
            )
        if entry.changed_hosts:
            lines.extend(["", "### Changed"] + [f"- `{host}`" for host in entry.changed_hosts])
    return "\n".join(lines).rstrip() + "\n"


def _render_device_search_terminal(search: DeviceSearchResult) -> str:
    if not search.matches:
        return f"No devices matched '{search.query}'."
    if len(search.matches) == 1:
        return _render_device_report_terminal(search.matches[0])
    lines = [
        _color("=" * 72, "cyan"),
        f"{_color('Device Matches', 'cyan')} query={search.query}",
        _color("-" * 72, "cyan"),
    ]
    for report in search.matches[:10]:
        lines.append(
            f"{_format_device_key(report.device_key)}  "
            f"vendor={report.vendor or 'unknown-vendor'}  "
            f"sessions={report.session_count}  "
            f"ips={', '.join(report.ip_addresses[:4]) or 'none'}"
        )
    lines.append(_color("=" * 72, "cyan"))
    return "\n".join(lines)


def _render_device_search_markdown(search: DeviceSearchResult) -> str:
    if not search.matches:
        return f"# Device search\n\nNo devices matched `{search.query}`.\n"
    if len(search.matches) == 1:
        return _render_device_report_markdown(search.matches[0])
    lines = [f"# Device Matches for `{search.query}`", ""]
    for report in search.matches[:10]:
        lines.append(
            f"- `{_format_device_key(report.device_key)}` "
            f"vendor=`{report.vendor or 'unknown-vendor'}` "
            f"sessions=`{report.session_count}` "
            f"ips=`{', '.join(report.ip_addresses[:4]) or 'none'}`"
        )
    return "\n".join(lines).rstrip() + "\n"


def _render_device_report_terminal(report: DeviceReport) -> str:
    lines = [
        _color("=" * 72, "cyan"),
        f"{_color('Device Timeline', 'cyan')} {_format_device_key(report.device_key)}",
        _color("-" * 72, "cyan"),
        f"Vendor    : {report.vendor or 'unknown-vendor'}",
        f"MAC       : {report.mac_address or 'none'}",
        f"IPs       : {', '.join(report.ip_addresses) if report.ip_addresses else 'none'}",
        f"Sessions  : {report.session_count}",
        f"First seen: {report.first_seen_session_id or 'unknown'}",
        f"Last seen : {report.last_seen_session_id or 'unknown'}",
        "",
        _color("Appearances", "cyan"),
        _color("-" * 72, "cyan"),
    ]
    for entry in sorted(report.sessions, key=lambda item: item.started_at):
        lines.append(
            f"#{entry.session_id} {_render_timestamp(entry.started_at)}  "
            f"ip={entry.ip_address or 'unknown'}  status={entry.status}"
        )
        lines.append(f"  target : {entry.target_input}")
        lines.append(f"  ports  : {' | '.join(entry.ports) if entry.ports else 'none'}")
        if entry.top_os:
            lines.append(f"  os     : {entry.top_os}")
    lines.append(_color("=" * 72, "cyan"))
    return "\n".join(lines)


def _render_device_report_markdown(report: DeviceReport) -> str:
    lines = [
        f"# Device {report.device_key}",
        "",
        f"- Vendor: `{report.vendor or 'unknown-vendor'}`",
        f"- MAC: `{report.mac_address or 'none'}`",
        f"- IPs: `{', '.join(report.ip_addresses) if report.ip_addresses else 'none'}`",
        f"- Sessions: `{report.session_count}`",
        "",
        "## Appearances",
        "",
    ]
    for entry in sorted(report.sessions, key=lambda item: item.started_at):
        lines.extend(
            [
                f"### Session {entry.session_id}",
                "",
                f"- Seen at: `{_render_timestamp(entry.started_at)}`",
                f"- Target: `{entry.target_input}`",
                f"- IP: `{entry.ip_address or 'unknown'}`",
                f"- Status: `{entry.status}`",
                f"- Ports: `{', '.join(entry.ports) if entry.ports else 'none'}`",
            ]
        )
        if entry.top_os:
            lines.append(f"- OS: `{entry.top_os}`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _render_timestamp(value: object) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S") if hasattr(value, "strftime") else str(value)


def _device_key_for_host(host: HostObservation) -> str:
    mac_address = host.device.mac_address if host.device and host.device.mac_address else None
    if mac_address:
        return mac_address
    ip_address = host.ip_address.ip_address if host.ip_address else "unknown-ip"
    return f"ip:{ip_address}"


def _top_os_name(host: HostObservation) -> str | None:
    if not host.os_matches:
        return None
    top_match = max(host.os_matches, key=lambda item: item.accuracy or 0)
    return top_match.name


def _match_host_query(host: HostObservation, host_query: str) -> bool:
    ip_address = host.ip_address.ip_address if host.ip_address else ""
    hostnames = _decode_json_list(host.hostnames_json)
    return fuzzy_match(host_query, ip_address, *hostnames)

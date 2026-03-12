from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class ScanOptions:
    target: str | None
    dev_mode: bool
    check_only: bool
    list_sessions: bool
    diff_ids: tuple[int, int] | None
    diff_global: bool
    devices_mode: bool
    device_query: str | None
    session_mode: bool
    session_id: int | None
    host_query: str | None
    delete_id: int | None
    timeline_mode: bool
    limit: int
    out_format: str
    out_path: Path | None
    status_filter: str | None
    target_filter: str | None
    vendor_filter: str | None
    mac_only: bool
    ip_only: bool
    ports: str | None
    output: Path
    db_path: Path | None
    save_mode: str
    verbose: bool
    name: str | None
    timing: str
    top_ports: int | None
    no_ping: bool
    service_version: bool
    os_detect: bool
    use_sudo: bool
    detail_workers: int

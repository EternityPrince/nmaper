from __future__ import annotations

import ipaddress
import json
import socket
import time
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.model import ScanOptions
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
from src.nmaper import ScanExecutionResult
from src.parser import ParsedHost, ParsedPort, ParsedScriptResult
from src.termui import log


def start_scan_session(session: Session, options: ScanOptions, started_at: datetime) -> ScanSession:
    log.phase("Opening database session")
    scan_session = ScanSession(
        started_at=started_at,
        target_input=options.target,
        target_cidr=_normalized_cidr(options.target),
        scanner_host=socket.gethostname(),
        nmap_command="",
        status="running",
    )
    session.add(scan_session)
    session.commit()
    session.refresh(scan_session)
    log.success(f"Scan session #{scan_session.id} created for target {options.target}")
    return scan_session


def complete_scan_session(
    session: Session,
    scan_session: ScanSession,
    options: ScanOptions,
    result: ScanExecutionResult,
    finished_at: datetime,
) -> None:
    started_at = time.monotonic()
    log.phase(f"Persisting scan session #{scan_session.id} to SQLite")
    scan_session.finished_at = finished_at
    scan_session.duration_seconds = (finished_at - scan_session.started_at).total_seconds()
    scan_session.nmap_command = " ; ".join(
        [_render_command(result.discovery_command)]
        + [_render_command(command) for command in result.detail_commands.values()]
    )
    scan_session.nmap_version = result.discovery_run.version
    scan_session.exit_status = 0
    scan_session.status = "completed"
    scan_session.notes = _build_session_notes(result)

    network = _get_or_create_network(session, options.target, scan_session.id)
    if network is not None:
        session_network = session.get(SessionNetwork, (scan_session.id, network.id))
        if session_network is None:
            session_network = SessionNetwork(
                session_id=scan_session.id,
                network_id=network.id,
            )
            session.add(session_network)
        session_network.discovered_host_count = len(result.discovery_run.hosts)
        session_network.live_host_count = sum(
            1 for host in result.discovery_run.hosts if host.status == "up"
        )

    for discovery_host in result.discovery_run.hosts:
        detail_host = _detail_host_for(discovery_host, result)
        _persist_host(session, scan_session, network, discovery_host, detail_host)

    session.commit()
    log.success(
        f"SQLite commit complete for session #{scan_session.id}: "
        f"{len(result.discovery_run.hosts)} host observation(s) stored "
        f"in {_format_duration(time.monotonic() - started_at)}"
    )


def fail_scan_session(
    session: Session,
    scan_session: ScanSession,
    error: Exception,
    finished_at: datetime,
) -> None:
    log.error(f"Marking scan session #{scan_session.id} as failed: {error}")
    scan_session.finished_at = finished_at
    scan_session.duration_seconds = (finished_at - scan_session.started_at).total_seconds()
    scan_session.exit_status = 1
    scan_session.status = "failed"
    scan_session.notes = str(error)
    session.commit()


def _persist_host(
    session: Session,
    scan_session: ScanSession,
    network: Network | None,
    discovery_host: ParsedHost,
    detail_host: ParsedHost | None,
) -> None:
    source_host = detail_host or discovery_host
    primary_ip = discovery_host.primary_ip
    if primary_ip is None:
        return

    device = _get_or_create_device(session, discovery_host, scan_session.id)
    ip_record = _get_or_create_ip_record(
        session=session,
        device=device,
        ip_address=primary_ip,
        session_id=scan_session.id,
        network=network,
    )
    host_observation = HostObservation(
        session_id=scan_session.id,
        device_id=device.id,
        ip_address_id=ip_record.id,
        status=source_host.status,
        hostnames_json=_json_or_none(source_host.hostnames),
        uptime_seconds=source_host.uptime_seconds,
        distance_hops=source_host.distance_hops,
        os_fingerprint=source_host.os_fingerprint,
        raw_nmap_xml=source_host.raw_xml,
    )
    session.add(host_observation)
    session.flush()

    for os_match in source_host.os_matches:
        session.add(
            OSMatch(
                host_observation_id=host_observation.id,
                name=os_match.name,
                accuracy=os_match.accuracy,
                line=os_match.line,
            )
        )

    for port in source_host.ports:
        _persist_service_observation(session, host_observation.id, port)

    for script in source_host.host_scripts:
        _persist_script_result(session, host_observation_id=host_observation.id, script=script)

    if source_host.trace_hops:
        trace = Trace(host_observation_id=host_observation.id)
        session.add(trace)
        session.flush()
        for hop in source_host.trace_hops:
            session.add(
                TraceHop(
                    trace_id=trace.id,
                    hop_index=hop.ttl,
                    ip_address=hop.ip_address,
                    rtt=hop.rtt,
                    hostname=hop.host,
                )
            )


def _persist_service_observation(
    session: Session, host_observation_id: int, port: ParsedPort
) -> None:
    db_port = _get_or_create_port(session, port.protocol, port.port_id)
    service_observation = ServiceObservation(
        host_observation_id=host_observation_id,
        port_id=db_port.id,
        state=port.state,
        reason=port.reason,
        service_name=port.service_name,
        product=port.product,
        version=port.version,
        extra_info=port.extra_info,
        tunnel=port.tunnel,
        method=port.method,
        conf=port.conf,
        cpe_json=_json_or_none(port.cpe),
    )
    session.add(service_observation)
    session.flush()

    for script in port.scripts:
        _persist_script_result(
            session, service_observation_id=service_observation.id, script=script
        )


def _persist_script_result(
    session: Session,
    script: ParsedScriptResult,
    host_observation_id: int | None = None,
    service_observation_id: int | None = None,
) -> None:
    db_script = _get_or_create_script(session, script.script_id)
    session.add(
        ScriptResult(
            service_observation_id=service_observation_id,
            host_observation_id=host_observation_id,
            script_id=db_script.id,
            output=script.output or "",
            elements_json=_json_or_none(script.elements),
        )
    )


def _get_or_create_device(session: Session, host: ParsedHost, session_id: int) -> Device:
    device: Device | None = None
    if host.mac_address:
        device = session.scalar(select(Device).where(Device.mac_address == host.mac_address))

    if device is None and host.primary_ip is not None:
        ip_record = session.scalar(
            select(DeviceIPAddress).where(DeviceIPAddress.ip_address == host.primary_ip)
        )
        if ip_record is not None:
            device = ip_record.device

    if device is None:
        device = Device(
            mac_address=host.mac_address,
            vendor=host.mac_vendor,
            first_seen_session_id=session_id,
            last_seen_session_id=session_id,
        )
        session.add(device)
        session.flush()
        return device

    if host.mac_address and device.mac_address is None:
        device.mac_address = host.mac_address
    if host.mac_vendor:
        device.vendor = host.mac_vendor
    if device.first_seen_session_id is None:
        device.first_seen_session_id = session_id
    device.last_seen_session_id = session_id
    session.flush()
    return device


def _get_or_create_ip_record(
    session: Session,
    device: Device,
    ip_address: str,
    session_id: int,
    network: Network | None,
) -> DeviceIPAddress:
    ip_record = session.scalar(
        select(DeviceIPAddress).where(
            DeviceIPAddress.device_id == device.id,
            DeviceIPAddress.ip_address == ip_address,
        )
    )
    if ip_record is None:
        ip_record = DeviceIPAddress(
            device_id=device.id,
            ip_address=ip_address,
            ip_version=ipaddress.ip_address(ip_address).version,
            network_id=network.id if network is not None else None,
            first_seen_session_id=session_id,
            last_seen_session_id=session_id,
        )
        session.add(ip_record)
        session.flush()
        return ip_record

    ip_record.network_id = network.id if network is not None else ip_record.network_id
    if ip_record.first_seen_session_id is None:
        ip_record.first_seen_session_id = session_id
    ip_record.last_seen_session_id = session_id
    session.flush()
    return ip_record


def _get_or_create_network(session: Session, target: str, session_id: int) -> Network | None:
    normalized = _normalized_cidr(target)
    if normalized is None:
        return None
    network_obj = ipaddress.ip_network(normalized, strict=False)
    network = session.scalar(select(Network).where(Network.cidr == normalized))
    if network is None:
        network = Network(
            cidr=normalized,
            ip_version=network_obj.version,
            network_address=str(network_obj.network_address),
            prefix_length=network_obj.prefixlen,
            first_seen_session_id=session_id,
            last_seen_session_id=session_id,
        )
        session.add(network)
        session.flush()
        return network

    if network.first_seen_session_id is None:
        network.first_seen_session_id = session_id
    network.last_seen_session_id = session_id
    session.flush()
    return network


def _get_or_create_port(session: Session, protocol: str, port_number: int) -> Port:
    db_port = session.scalar(
        select(Port).where(
            Port.protocol == protocol,
            Port.port_number == port_number,
        )
    )
    if db_port is None:
        db_port = Port(protocol=protocol, port_number=port_number)
        session.add(db_port)
        session.flush()
    return db_port


def _get_or_create_script(session: Session, name: str) -> Script:
    script = session.scalar(select(Script).where(Script.name == name))
    if script is None:
        script = Script(name=name)
        session.add(script)
        session.flush()
    return script


def _detail_host_for(discovery_host: ParsedHost, result: ScanExecutionResult) -> ParsedHost | None:
    primary_ip = discovery_host.primary_ip
    if primary_ip is None:
        return None
    detail_result = result.detail_runs.get(primary_ip)
    if detail_result is None or not detail_result.parsed_run.hosts:
        return None
    return detail_result.parsed_run.hosts[0]


def _build_session_notes(result: ScanExecutionResult) -> str | None:
    notes: dict[str, object] = {}
    if result.discovery_xml_path is not None:
        notes["discovery_xml_path"] = str(result.discovery_xml_path)
    if result.detail_errors:
        notes["detail_errors"] = result.detail_errors
    detail_xml_paths = {
        ip_address: str(detail.xml_path)
        for ip_address, detail in result.detail_runs.items()
        if detail.xml_path is not None
    }
    if detail_xml_paths:
        notes["detail_xml_paths"] = detail_xml_paths
    return json.dumps(notes, ensure_ascii=True) if notes else None


def _normalized_cidr(target: str) -> str | None:
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return None
    return str(network)


def _json_or_none(value: object) -> str | None:
    if value in (None, [], {}, ""):
        return None
    return json.dumps(value, ensure_ascii=True)


def _render_command(command: list[str]) -> str:
    return " ".join(command)


def _format_duration(seconds: float) -> str:
    total_seconds = max(0, int(round(seconds)))
    minutes, secs = divmod(total_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"

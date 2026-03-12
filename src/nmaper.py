from __future__ import annotations

import shlex
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from src.converter import collect_open_ports_by_host
from src.model import ScanOptions
from src.parser import ParsedNmapRun, parse_nmap_xml
from src.termui import log


@dataclass(slots=True)
class DetailScanResult:
    ip_address: str
    parsed_run: ParsedNmapRun
    command: list[str]
    xml_path: Path | None
    duration_seconds: float


@dataclass(slots=True)
class ScanExecutionResult:
    session_name: str
    session_dir: Path | None
    discovery_run: ParsedNmapRun
    discovery_duration_seconds: float
    detail_runs: dict[str, DetailScanResult]
    detail_errors: dict[str, str]
    discovery_command: list[str]
    detail_commands: dict[str, list[str]]
    discovery_xml_path: Path | None
    total_duration_seconds: float


class NmapExecutionError(RuntimeError):
    pass


def run_scan(options: ScanOptions) -> ScanExecutionResult:
    started_at = time.monotonic()
    log.phase("Bootstrapping nmap runtime")
    _ensure_nmap_available()
    _ensure_sudo_ready(options)
    session_name = options.name or datetime.now().strftime("%Y%m%d-%H%M%S")
    session_dir = _session_dir(options, session_name)
    if options.save_mode == "xml" and session_dir is not None:
        (session_dir / "xml").mkdir(parents=True, exist_ok=True)
        log.info(f"XML output directory armed at {session_dir / 'xml'}")

    discovery_command = build_discovery_command(options)
    log.phase(f"Starting discovery scan for target {options.target}")
    discovery_xml_path = _xml_output_path(session_dir, "discovery", options.save_mode)
    discovery_run, discovery_duration = _execute_and_parse(discovery_command, discovery_xml_path)
    log.success(
        "Discovery scan completed: "
        f"{len(discovery_run.hosts)} hosts observed, "
        f"{len(collect_open_ports_by_host(discovery_run))} hosts with open ports "
        f"in {_format_duration(discovery_duration)}"
    )

    open_ports_by_host = collect_open_ports_by_host(discovery_run)
    detail_runs: dict[str, DetailScanResult] = {}
    detail_errors: dict[str, str] = {}
    detail_commands: dict[str, list[str]] = {}

    if open_ports_by_host:
        max_workers = max(1, options.detail_workers)
        log.phase(
            "Starting detailed host scans "
            f"with {max_workers} worker(s) for {len(open_ports_by_host)} host(s)"
        )
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            total_hosts = len(open_ports_by_host)
            completed_hosts = 0
            for ip_address, ports in open_ports_by_host.items():
                command = build_detail_command(options, ip_address, ports)
                detail_commands[ip_address] = command
                xml_path = _xml_output_path(
                    session_dir, f"host-{ip_address.replace(':', '_')}", options.save_mode
                )
                future = executor.submit(_execute_and_parse, command, xml_path)
                futures[future] = (ip_address, command, xml_path, len(ports))

            for future in as_completed(futures):
                ip_address, command, xml_path, port_count = futures[future]
                try:
                    parsed_run, duration_seconds = future.result()
                except Exception as exc:
                    detail_errors[ip_address] = str(exc)
                    completed_hosts += 1
                    log.warn(
                        f"[{completed_hosts}/{total_hosts}] host {ip_address} failed "
                        f"after {_format_duration_from_error(exc)}"
                    )
                    continue
                completed_hosts += 1
                detail_runs[ip_address] = DetailScanResult(
                    ip_address=ip_address,
                    parsed_run=parsed_run,
                    command=command,
                    xml_path=xml_path,
                    duration_seconds=duration_seconds,
                )
                open_ports = sum(
                    1 for host in parsed_run.hosts for port in host.ports if port.state == "open"
                )
                log.success(
                    f"[{completed_hosts}/{total_hosts}] host {ip_address} "
                    f"done in {_format_duration(duration_seconds)} "
                    f"({open_ports} open ports from {port_count} target ports)"
                )
    else:
        log.warn("Discovery stage found no hosts with open ports; skipping detailed scans")

    if options.save_mode == "xml" and session_dir is not None:
        log.success(f"XML artifacts written to {session_dir / 'xml'}")

    return ScanExecutionResult(
        session_name=session_name,
        session_dir=session_dir,
        discovery_run=discovery_run,
        detail_runs=detail_runs,
        detail_errors=detail_errors,
        discovery_command=discovery_command,
        detail_commands=detail_commands,
        discovery_xml_path=discovery_xml_path,
        discovery_duration_seconds=discovery_duration,
        total_duration_seconds=time.monotonic() - started_at,
    )


def build_discovery_command(options: ScanOptions) -> list[str]:
    command = _command_prefix(options)
    scan_type = "-sS" if options.use_sudo else "-sT"
    command.extend(["nmap", scan_type, options.target, "-T", options.timing, "-oX", "-"])
    if options.no_ping:
        command.append("-Pn")
    if options.ports:
        command.extend(["-p", options.ports])
    elif options.top_ports is not None:
        command.extend(["--top-ports", str(options.top_ports)])
    return command


def build_detail_command(options: ScanOptions, ip_address: str, ports: list[int]) -> list[str]:
    command = _command_prefix(options)
    command.extend(
        [
            "nmap",
            ip_address,
            "-T",
            options.timing,
            "-oX",
            "-",
            "-p",
            ",".join(str(port) for port in ports),
        ]
    )
    if options.service_version or options.os_detect:
        if options.service_version:
            command.append("-sV")
        if options.os_detect:
            command.append("-O")
    else:
        command.append("-A")
    if options.no_ping:
        command.append("-Pn")
    return command


def summarize_scan(result: ScanExecutionResult) -> str:
    total_hosts = len(result.discovery_run.hosts)
    detailed_hosts = len(result.detail_runs)
    return (
        f"session={result.session_name} "
        f"hosts={total_hosts} "
        f"detailed={detailed_hosts} "
        f"detail_errors={len(result.detail_errors)} "
        f"discovery={_format_duration(result.discovery_duration_seconds)} "
        f"total={_format_duration(result.total_duration_seconds)} "
        f"dir={result.session_dir or 'db-only'}"
    )


def _command_prefix(options: ScanOptions) -> list[str]:
    if options.use_sudo:
        return ["sudo", "-n"]
    return []


def _ensure_nmap_available() -> None:
    if shutil.which("nmap") is None:
        raise NmapExecutionError("nmap is not installed or not found in PATH")
    log.success("nmap binary located in PATH")


def _ensure_sudo_ready(options: ScanOptions) -> None:
    if not options.use_sudo:
        return
    log.phase("Acquiring sudo credentials")
    try:
        subprocess.run(["sudo", "-v"], check=True)
    except subprocess.CalledProcessError as exc:
        raise NmapExecutionError("failed to acquire sudo credentials") from exc
    log.success("sudo session is warm")


def _execute_and_parse(command: list[str], xml_path: Path | None) -> tuple[ParsedNmapRun, float]:
    started_at = time.monotonic()
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        rendered = shlex.join(command)
        raise NmapExecutionError(
            f"command failed ({completed.returncode}): {rendered}\n{completed.stderr.strip()}"
        )
    if xml_path is not None:
        xml_path.write_text(completed.stdout, encoding="utf-8")
    return parse_nmap_xml(completed.stdout), time.monotonic() - started_at


def _xml_output_path(session_dir: Path | None, name: str, save_mode: str) -> Path | None:
    if save_mode != "xml" or session_dir is None:
        return None
    return session_dir / "xml" / f"{name}.xml"


def _session_dir(options: ScanOptions, session_name: str) -> Path | None:
    if options.save_mode != "xml":
        return None
    return options.output.expanduser().resolve() / session_name


def _render_command(command: list[str]) -> str:
    return shlex.join(command)


def _format_duration(seconds: float) -> str:
    total_seconds = max(0, int(round(seconds)))
    minutes, secs = divmod(total_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def _format_duration_from_error(error: Exception) -> str:
    duration = getattr(error, "duration_seconds", None)
    if isinstance(duration, (int, float)):
        return _format_duration(duration)
    return "unknown time"

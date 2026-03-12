from __future__ import annotations

from dataclasses import dataclass

from src.parser import ParsedHost, ParsedNmapRun, ParsedPort


@dataclass(slots=True)
class HostPortTarget:
    ip_address: str
    ports: list[int]


def collect_open_ports_by_host(parsed_run: ParsedNmapRun) -> dict[str, list[int]]:
    port_map: dict[str, list[int]] = {}
    for host in parsed_run.hosts:
        ip_address = host.primary_ip
        if ip_address is None:
            continue
        open_ports = sorted(port.port_id for port in host.ports if port.state == "open")
        if open_ports:
            port_map[ip_address] = open_ports
    return port_map


def to_host_port_targets(parsed_run: ParsedNmapRun) -> list[HostPortTarget]:
    return [
        HostPortTarget(ip_address=ip_address, ports=ports)
        for ip_address, ports in collect_open_ports_by_host(parsed_run).items()
    ]


def get_open_ports(host: ParsedHost) -> list[ParsedPort]:
    return [port for port in host.ports if port.state == "open"]

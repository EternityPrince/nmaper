from __future__ import annotations

from dataclasses import dataclass, field
from xml.etree import ElementTree as ET


@dataclass(slots=True)
class ParsedAddress:
    address: str
    addrtype: str
    vendor: str | None = None


@dataclass(slots=True)
class ParsedScriptResult:
    script_id: str
    output: str | None
    elements: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class ParsedPort:
    protocol: str
    port_id: int
    state: str
    reason: str | None
    service_name: str | None
    product: str | None
    version: str | None
    extra_info: str | None
    tunnel: str | None
    method: str | None
    conf: int | None
    cpe: list[str] = field(default_factory=list)
    scripts: list[ParsedScriptResult] = field(default_factory=list)


@dataclass(slots=True)
class ParsedOSMatch:
    name: str
    accuracy: int | None
    line: str | None


@dataclass(slots=True)
class ParsedTraceHop:
    ttl: int
    ip_address: str | None
    rtt: float | None
    host: str | None


@dataclass(slots=True)
class ParsedHost:
    ipv4: str | None
    ipv6: str | None
    mac_address: str | None
    mac_vendor: str | None
    status: str
    latency: float | None
    hostnames: list[str] = field(default_factory=list)
    ports: list[ParsedPort] = field(default_factory=list)
    os_matches: list[ParsedOSMatch] = field(default_factory=list)
    host_scripts: list[ParsedScriptResult] = field(default_factory=list)
    trace_hops: list[ParsedTraceHop] = field(default_factory=list)
    distance_hops: int | None = None
    uptime_seconds: int | None = None
    service_info: dict[str, str] = field(default_factory=dict)
    os_fingerprint: str | None = None
    raw_xml: str | None = None

    @property
    def primary_ip(self) -> str | None:
        return self.ipv4 or self.ipv6


@dataclass(slots=True)
class ParsedRunStats:
    finished_at: str | None
    elapsed_seconds: float | None
    total_hosts: int | None
    up_hosts: int | None
    down_hosts: int | None


@dataclass(slots=True)
class ParsedNmapRun:
    scanner: str | None
    args: str | None
    start_time: str | None
    version: str | None
    hosts: list[ParsedHost]
    stats: ParsedRunStats
    raw_xml: str


def parse_nmap_xml(xml_text: str) -> ParsedNmapRun:
    root = ET.fromstring(xml_text)
    hosts = [_parse_host(host_elem) for host_elem in root.findall("host")]
    return ParsedNmapRun(
        scanner=root.attrib.get("scanner"),
        args=root.attrib.get("args"),
        start_time=root.attrib.get("startstr"),
        version=root.attrib.get("version"),
        hosts=hosts,
        stats=_parse_run_stats(root.find("runstats")),
        raw_xml=xml_text,
    )


def _parse_host(host_elem: ET.Element) -> ParsedHost:
    addresses = _parse_addresses(host_elem)
    status_elem = host_elem.find("status")
    status = status_elem.attrib.get("state", "unknown") if status_elem is not None else "unknown"
    latency = (
        _float_or_none(status_elem.attrib.get("reason_ttl")) if status_elem is not None else None
    )
    if status_elem is not None and status_elem.attrib.get("reason") == "localhost-response":
        latency = 0.0
    times_elem = host_elem.find("times")
    if times_elem is not None and times_elem.attrib.get("srtt"):
        latency = int(times_elem.attrib["srtt"]) / 1_000_000

    ipv4 = _get_address(addresses, "ipv4")
    ipv6 = _get_address(addresses, "ipv6")
    mac = next((addr for addr in addresses if addr.addrtype == "mac"), None)
    uptime_elem = host_elem.find("uptime")
    distance_elem = host_elem.find("distance")
    os_fingerprint_elem = host_elem.find("os/osfingerprint")

    return ParsedHost(
        ipv4=ipv4.address if ipv4 else None,
        ipv6=ipv6.address if ipv6 else None,
        mac_address=mac.address if mac else None,
        mac_vendor=mac.vendor if mac else None,
        status=status,
        latency=latency,
        hostnames=[
            elem.attrib["name"]
            for elem in host_elem.findall("hostnames/hostname")
            if "name" in elem.attrib
        ],
        ports=[_parse_port(port_elem) for port_elem in host_elem.findall("ports/port")],
        os_matches=[_parse_os_match(match_elem) for match_elem in host_elem.findall("os/osmatch")],
        host_scripts=[
            _parse_script(script_elem) for script_elem in host_elem.findall("hostscript/script")
        ],
        trace_hops=[_parse_trace_hop(hop_elem) for hop_elem in host_elem.findall("trace/hop")],
        distance_hops=_int_or_none(distance_elem.attrib.get("value"))
        if distance_elem is not None
        else None,
        uptime_seconds=_int_or_none(uptime_elem.attrib.get("seconds"))
        if uptime_elem is not None
        else None,
        service_info=_parse_service_info(host_elem.find("service")),
        os_fingerprint=os_fingerprint_elem.attrib.get("fingerprint")
        if os_fingerprint_elem is not None
        else None,
        raw_xml=ET.tostring(host_elem, encoding="unicode"),
    )


def _parse_addresses(host_elem: ET.Element) -> list[ParsedAddress]:
    return [
        ParsedAddress(
            address=addr.attrib["addr"],
            addrtype=addr.attrib["addrtype"],
            vendor=addr.attrib.get("vendor"),
        )
        for addr in host_elem.findall("address")
        if "addr" in addr.attrib and "addrtype" in addr.attrib
    ]


def _get_address(addresses: list[ParsedAddress], addrtype: str) -> ParsedAddress | None:
    return next((address for address in addresses if address.addrtype == addrtype), None)


def _parse_port(port_elem: ET.Element) -> ParsedPort:
    state_elem = port_elem.find("state")
    service_elem = port_elem.find("service")
    return ParsedPort(
        protocol=port_elem.attrib["protocol"],
        port_id=int(port_elem.attrib["portid"]),
        state=state_elem.attrib.get("state", "unknown") if state_elem is not None else "unknown",
        reason=state_elem.attrib.get("reason") if state_elem is not None else None,
        service_name=service_elem.attrib.get("name") if service_elem is not None else None,
        product=service_elem.attrib.get("product") if service_elem is not None else None,
        version=service_elem.attrib.get("version") if service_elem is not None else None,
        extra_info=service_elem.attrib.get("extrainfo") if service_elem is not None else None,
        tunnel=service_elem.attrib.get("tunnel") if service_elem is not None else None,
        method=service_elem.attrib.get("method") if service_elem is not None else None,
        conf=_int_or_none(service_elem.attrib.get("conf")) if service_elem is not None else None,
        cpe=[cpe_elem.text for cpe_elem in port_elem.findall("service/cpe") if cpe_elem.text],
        scripts=[_parse_script(script_elem) for script_elem in port_elem.findall("script")],
    )


def _parse_os_match(match_elem: ET.Element) -> ParsedOSMatch:
    return ParsedOSMatch(
        name=match_elem.attrib["name"],
        accuracy=_int_or_none(match_elem.attrib.get("accuracy")),
        line=match_elem.attrib.get("line"),
    )


def _parse_trace_hop(hop_elem: ET.Element) -> ParsedTraceHop:
    return ParsedTraceHop(
        ttl=int(hop_elem.attrib["ttl"]),
        ip_address=hop_elem.attrib.get("ipaddr"),
        rtt=_float_or_none(hop_elem.attrib.get("rtt")),
        host=hop_elem.attrib.get("host"),
    )


def _parse_script(script_elem: ET.Element) -> ParsedScriptResult:
    return ParsedScriptResult(
        script_id=script_elem.attrib["id"],
        output=script_elem.attrib.get("output"),
        elements=_parse_script_children(script_elem),
    )


def _parse_script_children(parent: ET.Element) -> dict[str, object]:
    data: dict[str, object] = {}
    for child in parent:
        key = child.attrib.get("key") or child.attrib.get("name") or child.tag
        value = _parse_script_value(child)
        if key in data:
            existing = data[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                data[key] = [existing, value]
        else:
            data[key] = value
    return data


def _parse_script_value(elem: ET.Element) -> object:
    if elem.tag == "elem":
        return elem.text or ""
    if elem.tag == "table":
        return _parse_script_children(elem)
    return {
        "attributes": dict(elem.attrib),
        "text": elem.text or "",
    }


def _parse_service_info(elem: ET.Element | None) -> dict[str, str]:
    if elem is None:
        return {}
    return {key: value for key, value in elem.attrib.items() if value}


def _parse_run_stats(runstats_elem: ET.Element | None) -> ParsedRunStats:
    if runstats_elem is None:
        return ParsedRunStats(
            finished_at=None,
            elapsed_seconds=None,
            total_hosts=None,
            up_hosts=None,
            down_hosts=None,
        )
    finished = runstats_elem.find("finished")
    hosts = runstats_elem.find("hosts")
    return ParsedRunStats(
        finished_at=finished.attrib.get("timestr") if finished is not None else None,
        elapsed_seconds=_float_or_none(finished.attrib.get("elapsed"))
        if finished is not None
        else None,
        total_hosts=_int_or_none(hosts.attrib.get("total")) if hosts is not None else None,
        up_hosts=_int_or_none(hosts.attrib.get("up")) if hosts is not None else None,
        down_hosts=_int_or_none(hosts.attrib.get("down")) if hosts is not None else None,
    )


def _int_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    return int(value)


def _float_or_none(value: str | None) -> float | None:
    if value is None:
        return None
    return float(value)

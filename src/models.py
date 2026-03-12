from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Literal

from sqlalchemy import CheckConstraint, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

SessionStatus = Literal["running", "completed", "failed"]
HostStatus = Literal["up", "down", "unknown"]
IPVersion = Literal[4, 6]
PortProtocol = Literal["tcp", "udp", "sctp", "ip"]


class Base(DeclarativeBase):
    pass


class ScanSession(Base):
    __tablename__ = "scan_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    started_at: Mapped[datetime]
    finished_at: Mapped[datetime | None]
    duration_seconds: Mapped[float | None] = mapped_column(Float)
    target_input: Mapped[str] = mapped_column(Text)
    target_cidr: Mapped[str | None] = mapped_column(String(128))
    scanner_host: Mapped[str | None] = mapped_column(String(255))
    nmap_command: Mapped[str] = mapped_column(Text)
    nmap_version: Mapped[str | None] = mapped_column(String(64))
    exit_status: Mapped[int | None]
    status: Mapped[SessionStatus] = mapped_column(String(16), default="completed")
    notes: Mapped[str | None] = mapped_column(Text)

    session_networks: Mapped[list[SessionNetwork]] = relationship(back_populates="session")
    host_observations: Mapped[list[HostObservation]] = relationship(back_populates="session")

    __table_args__ = (
        CheckConstraint(
            "status IN ('running', 'completed', 'failed')", name="ck_scan_sessions_status"
        ),
    )


class Network(Base):
    __tablename__ = "networks"

    id: Mapped[int] = mapped_column(primary_key=True)
    cidr: Mapped[str] = mapped_column(String(128), unique=True)
    ip_version: Mapped[IPVersion] = mapped_column(Integer)
    network_address: Mapped[str] = mapped_column(String(128))
    prefix_length: Mapped[int]
    first_seen_session_id: Mapped[int | None] = mapped_column(ForeignKey("scan_sessions.id"))
    last_seen_session_id: Mapped[int | None] = mapped_column(ForeignKey("scan_sessions.id"))

    session_networks: Mapped[list[SessionNetwork]] = relationship(back_populates="network")
    ip_addresses: Mapped[list[DeviceIPAddress]] = relationship(back_populates="network")

    __table_args__ = (CheckConstraint("ip_version IN (4, 6)", name="ck_networks_ip_version"),)


class SessionNetwork(Base):
    __tablename__ = "session_networks"

    session_id: Mapped[int] = mapped_column(
        ForeignKey("scan_sessions.id", ondelete="CASCADE"), primary_key=True
    )
    network_id: Mapped[int] = mapped_column(
        ForeignKey("networks.id", ondelete="CASCADE"), primary_key=True
    )
    discovered_host_count: Mapped[int | None]
    live_host_count: Mapped[int | None]

    session: Mapped[ScanSession] = relationship(back_populates="session_networks")
    network: Mapped[Network] = relationship(back_populates="session_networks")


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    mac_address: Mapped[str | None] = mapped_column(String(32), unique=True)
    vendor: Mapped[str | None] = mapped_column(String(255))
    first_seen_session_id: Mapped[int | None] = mapped_column(ForeignKey("scan_sessions.id"))
    last_seen_session_id: Mapped[int | None] = mapped_column(ForeignKey("scan_sessions.id"))

    ip_addresses: Mapped[list[DeviceIPAddress]] = relationship(back_populates="device")
    host_observations: Mapped[list[HostObservation]] = relationship(back_populates="device")


class DeviceIPAddress(Base):
    __tablename__ = "device_ip_addresses"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    ip_address: Mapped[str] = mapped_column(String(128))
    ip_version: Mapped[IPVersion] = mapped_column(Integer)
    network_id: Mapped[int | None] = mapped_column(ForeignKey("networks.id"))
    first_seen_session_id: Mapped[int | None] = mapped_column(ForeignKey("scan_sessions.id"))
    last_seen_session_id: Mapped[int | None] = mapped_column(ForeignKey("scan_sessions.id"))

    device: Mapped[Device] = relationship(back_populates="ip_addresses")
    network: Mapped[Network] = relationship(back_populates="ip_addresses")
    host_observations: Mapped[list[HostObservation]] = relationship(back_populates="ip_address")

    __table_args__ = (
        UniqueConstraint("device_id", "ip_address", name="uq_device_ip_addresses_device_ip"),
        CheckConstraint("ip_version IN (4, 6)", name="ck_device_ip_addresses_ip_version"),
    )


class HostObservation(Base):
    __tablename__ = "host_observations"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scan_sessions.id", ondelete="CASCADE"))
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"))
    ip_address_id: Mapped[int | None] = mapped_column(ForeignKey("device_ip_addresses.id"))
    status: Mapped[HostStatus] = mapped_column(String(16))
    hostnames_json: Mapped[str | None] = mapped_column(Text)
    uptime_seconds: Mapped[int | None]
    distance_hops: Mapped[int | None]
    os_fingerprint: Mapped[str | None] = mapped_column(Text)
    raw_nmap_xml: Mapped[str | None] = mapped_column(Text)
    raw_nmap_normal: Mapped[str | None] = mapped_column(Text)
    raw_nmap_grepable: Mapped[str | None] = mapped_column(Text)

    session: Mapped[ScanSession] = relationship(back_populates="host_observations")
    device: Mapped[Device | None] = relationship(back_populates="host_observations")
    ip_address: Mapped[DeviceIPAddress | None] = relationship(back_populates="host_observations")
    os_matches: Mapped[list[OSMatch]] = relationship(back_populates="host_observation")
    service_observations: Mapped[list[ServiceObservation]] = relationship(
        back_populates="host_observation"
    )
    script_results: Mapped[list[ScriptResult]] = relationship(back_populates="host_observation")
    trace: Mapped[Trace | None] = relationship(back_populates="host_observation", uselist=False)

    __table_args__ = (
        UniqueConstraint("session_id", "ip_address_id", name="uq_host_observations_session_ip"),
        CheckConstraint("status IN ('up', 'down', 'unknown')", name="ck_host_observations_status"),
    )


class OSMatch(Base):
    __tablename__ = "os_matches"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_observation_id: Mapped[int] = mapped_column(
        ForeignKey("host_observations.id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String(255))
    accuracy: Mapped[int | None]
    line: Mapped[str | None] = mapped_column(Text)

    host_observation: Mapped[HostObservation] = relationship(back_populates="os_matches")


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(primary_key=True)
    protocol: Mapped[PortProtocol] = mapped_column(String(16))
    port_number: Mapped[int]

    service_observations: Mapped[list[ServiceObservation]] = relationship(back_populates="port")

    __table_args__ = (
        UniqueConstraint("protocol", "port_number", name="uq_ports_protocol_port_number"),
        CheckConstraint("protocol IN ('tcp', 'udp', 'sctp', 'ip')", name="ck_ports_protocol"),
    )


class ServiceObservation(Base):
    __tablename__ = "service_observations"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_observation_id: Mapped[int] = mapped_column(
        ForeignKey("host_observations.id", ondelete="CASCADE")
    )
    port_id: Mapped[int] = mapped_column(ForeignKey("ports.id"))
    state: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str | None] = mapped_column(String(255))
    service_name: Mapped[str | None] = mapped_column(String(255))
    product: Mapped[str | None] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(255))
    extra_info: Mapped[str | None] = mapped_column(Text)
    tunnel: Mapped[str | None] = mapped_column(String(64))
    method: Mapped[str | None] = mapped_column(String(64))
    conf: Mapped[int | None]
    cpe_json: Mapped[str | None] = mapped_column(Text)
    banner: Mapped[str | None] = mapped_column(Text)

    host_observation: Mapped[HostObservation] = relationship(back_populates="service_observations")
    port: Mapped[Port] = relationship(back_populates="service_observations")
    script_results: Mapped[list[ScriptResult]] = relationship(back_populates="service_observation")

    __table_args__ = (
        UniqueConstraint(
            "host_observation_id", "port_id", name="uq_service_observations_host_port"
        ),
    )


class Script(Base):
    __tablename__ = "scripts"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)

    script_results: Mapped[list[ScriptResult]] = relationship(back_populates="script")


class ScriptResult(Base):
    __tablename__ = "script_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    service_observation_id: Mapped[int | None] = mapped_column(
        ForeignKey("service_observations.id", ondelete="CASCADE")
    )
    host_observation_id: Mapped[int | None] = mapped_column(
        ForeignKey("host_observations.id", ondelete="CASCADE")
    )
    script_id: Mapped[int] = mapped_column(ForeignKey("scripts.id"))
    output: Mapped[str] = mapped_column(Text)
    elements_json: Mapped[str | None] = mapped_column(Text)

    service_observation: Mapped[ServiceObservation | None] = relationship(
        back_populates="script_results"
    )
    host_observation: Mapped[HostObservation | None] = relationship(back_populates="script_results")
    script: Mapped[Script] = relationship(back_populates="script_results")

    __table_args__ = (
        CheckConstraint(
            "service_observation_id IS NOT NULL OR host_observation_id IS NOT NULL",
            name="ck_script_results_parent_ref",
        ),
    )


class Trace(Base):
    __tablename__ = "traces"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_observation_id: Mapped[int] = mapped_column(
        ForeignKey("host_observations.id", ondelete="CASCADE"),
        unique=True,
    )
    protocol: Mapped[str | None] = mapped_column(String(32))
    port: Mapped[int | None]

    host_observation: Mapped[HostObservation] = relationship(back_populates="trace")
    hops: Mapped[list[TraceHop]] = relationship(back_populates="trace")


class TraceHop(Base):
    __tablename__ = "trace_hops"

    id: Mapped[int] = mapped_column(primary_key=True)
    trace_id: Mapped[int] = mapped_column(ForeignKey("traces.id", ondelete="CASCADE"))
    hop_index: Mapped[int]
    ip_address: Mapped[str | None] = mapped_column(String(128))
    rtt: Mapped[float | None] = mapped_column(Float)
    hostname: Mapped[str | None] = mapped_column(String(255))

    trace: Mapped[Trace] = relationship(back_populates="hops")

    __table_args__ = (
        UniqueConstraint("trace_id", "hop_index", name="uq_trace_hops_trace_hop_index"),
    )


def default_database_path() -> Path:
    return Path.home() / ".local" / "share" / "nmaper" / "nmaper.db"

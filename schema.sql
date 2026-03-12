PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scan_sessions (
    id INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    duration_seconds REAL,
    target_input TEXT NOT NULL,
    target_cidr TEXT,
    scanner_host TEXT,
    nmap_command TEXT NOT NULL,
    nmap_version TEXT,
    exit_status INTEGER,
    status TEXT NOT NULL DEFAULT 'completed' CHECK (status IN ('running', 'completed', 'failed')),
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_sessions_started_at
    ON scan_sessions(started_at);

CREATE TABLE IF NOT EXISTS networks (
    id INTEGER PRIMARY KEY,
    cidr TEXT NOT NULL UNIQUE,
    ip_version INTEGER NOT NULL CHECK (ip_version IN (4, 6)),
    network_address TEXT NOT NULL,
    prefix_length INTEGER NOT NULL,
    first_seen_session_id INTEGER,
    last_seen_session_id INTEGER,
    FOREIGN KEY (first_seen_session_id) REFERENCES scan_sessions(id),
    FOREIGN KEY (last_seen_session_id) REFERENCES scan_sessions(id)
);

CREATE TABLE IF NOT EXISTS session_networks (
    session_id INTEGER NOT NULL,
    network_id INTEGER NOT NULL,
    discovered_host_count INTEGER,
    live_host_count INTEGER,
    PRIMARY KEY (session_id, network_id),
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    mac_address TEXT UNIQUE,
    vendor TEXT,
    first_seen_session_id INTEGER,
    last_seen_session_id INTEGER,
    FOREIGN KEY (first_seen_session_id) REFERENCES scan_sessions(id),
    FOREIGN KEY (last_seen_session_id) REFERENCES scan_sessions(id)
);

CREATE TABLE IF NOT EXISTS device_ip_addresses (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL,
    ip_address TEXT NOT NULL,
    ip_version INTEGER NOT NULL CHECK (ip_version IN (4, 6)),
    network_id INTEGER,
    first_seen_session_id INTEGER,
    last_seen_session_id INTEGER,
    UNIQUE (device_id, ip_address),
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
    FOREIGN KEY (network_id) REFERENCES networks(id),
    FOREIGN KEY (first_seen_session_id) REFERENCES scan_sessions(id),
    FOREIGN KEY (last_seen_session_id) REFERENCES scan_sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_device_ip_addresses_ip
    ON device_ip_addresses(ip_address);

CREATE TABLE IF NOT EXISTS host_observations (
    id INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL,
    device_id INTEGER,
    ip_address_id INTEGER,
    status TEXT NOT NULL CHECK (status IN ('up', 'down', 'unknown')),
    hostnames_json TEXT,
    uptime_seconds INTEGER,
    distance_hops INTEGER,
    os_fingerprint TEXT,
    raw_nmap_xml TEXT,
    raw_nmap_normal TEXT,
    raw_nmap_grepable TEXT,
    UNIQUE (session_id, ip_address_id),
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices(id),
    FOREIGN KEY (ip_address_id) REFERENCES device_ip_addresses(id)
);

CREATE INDEX IF NOT EXISTS idx_host_observations_session_id
    ON host_observations(session_id);

CREATE TABLE IF NOT EXISTS os_matches (
    id INTEGER PRIMARY KEY,
    host_observation_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    accuracy INTEGER,
    line TEXT,
    FOREIGN KEY (host_observation_id) REFERENCES host_observations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY,
    protocol TEXT NOT NULL CHECK (protocol IN ('tcp', 'udp', 'sctp', 'ip')),
    port_number INTEGER NOT NULL,
    UNIQUE (protocol, port_number)
);

CREATE TABLE IF NOT EXISTS service_observations (
    id INTEGER PRIMARY KEY,
    host_observation_id INTEGER NOT NULL,
    port_id INTEGER NOT NULL,
    state TEXT NOT NULL,
    reason TEXT,
    service_name TEXT,
    product TEXT,
    version TEXT,
    extra_info TEXT,
    tunnel TEXT,
    method TEXT,
    conf INTEGER,
    cpe_json TEXT,
    banner TEXT,
    UNIQUE (host_observation_id, port_id),
    FOREIGN KEY (host_observation_id) REFERENCES host_observations(id) ON DELETE CASCADE,
    FOREIGN KEY (port_id) REFERENCES ports(id)
);

CREATE INDEX IF NOT EXISTS idx_service_observations_port
    ON service_observations(port_id, state);

CREATE TABLE IF NOT EXISTS scripts (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS script_results (
    id INTEGER PRIMARY KEY,
    service_observation_id INTEGER,
    host_observation_id INTEGER,
    script_id INTEGER NOT NULL,
    output TEXT NOT NULL,
    elements_json TEXT,
    CHECK (
        service_observation_id IS NOT NULL
        OR host_observation_id IS NOT NULL
    ),
    FOREIGN KEY (service_observation_id) REFERENCES service_observations(id) ON DELETE CASCADE,
    FOREIGN KEY (host_observation_id) REFERENCES host_observations(id) ON DELETE CASCADE,
    FOREIGN KEY (script_id) REFERENCES scripts(id)
);

CREATE TABLE IF NOT EXISTS traces (
    id INTEGER PRIMARY KEY,
    host_observation_id INTEGER NOT NULL UNIQUE,
    protocol TEXT,
    port INTEGER,
    FOREIGN KEY (host_observation_id) REFERENCES host_observations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS trace_hops (
    id INTEGER PRIMARY KEY,
    trace_id INTEGER NOT NULL,
    hop_index INTEGER NOT NULL,
    ip_address TEXT,
    rtt REAL,
    hostname TEXT,
    UNIQUE (trace_id, hop_index),
    FOREIGN KEY (trace_id) REFERENCES traces(id) ON DELETE CASCADE
);

package storage

const schemaSQL = `
CREATE TABLE IF NOT EXISTS scan_sessions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT,
	target TEXT NOT NULL,
	save_mode TEXT NOT NULL,
	started_at TEXT NOT NULL,
	completed_at TEXT,
	duration_ms INTEGER NOT NULL DEFAULT 0,
	status TEXT NOT NULL,
	error_text TEXT,
	nmap_version TEXT,
	discovery_command TEXT,
	detail_command_template TEXT,
	discovered_hosts INTEGER NOT NULL DEFAULT 0,
	live_hosts INTEGER NOT NULL DEFAULT 0,
	detail_scans INTEGER NOT NULL DEFAULT 0,
	detail_errors INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS networks (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	cidr TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS session_networks (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id INTEGER NOT NULL,
	network_id INTEGER NOT NULL,
	discovered_hosts INTEGER NOT NULL DEFAULT 0,
	live_hosts INTEGER NOT NULL DEFAULT 0,
	UNIQUE(session_id, network_id),
	FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE,
	FOREIGN KEY(network_id) REFERENCES networks(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS devices (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	mac TEXT UNIQUE,
	fallback_key TEXT UNIQUE,
	vendor TEXT,
	first_seen_session_id INTEGER,
	last_seen_session_id INTEGER,
	first_seen_at TEXT,
	last_seen_at TEXT
);

CREATE TABLE IF NOT EXISTS device_ip_addresses (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	device_id INTEGER NOT NULL,
	ip_address TEXT NOT NULL,
	ip_version INTEGER NOT NULL,
	network_id INTEGER,
	first_seen_session_id INTEGER,
	last_seen_session_id INTEGER,
	first_seen_at TEXT,
	last_seen_at TEXT,
	UNIQUE(device_id, ip_address),
	FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
	FOREIGN KEY(network_id) REFERENCES networks(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS host_observations (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id INTEGER NOT NULL,
	device_id INTEGER NOT NULL,
	primary_ip TEXT NOT NULL,
	status TEXT,
	mac TEXT,
	vendor TEXT,
	hostnames_json TEXT NOT NULL DEFAULT '[]',
	UNIQUE(session_id, primary_ip),
	FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE,
	FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS os_matches (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	host_observation_id INTEGER NOT NULL,
	name TEXT NOT NULL,
	accuracy INTEGER NOT NULL DEFAULT 0,
	os_class TEXT,
	FOREIGN KEY(host_observation_id) REFERENCES host_observations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ports (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	port INTEGER NOT NULL,
	protocol TEXT NOT NULL,
	UNIQUE(port, protocol)
);

CREATE TABLE IF NOT EXISTS service_observations (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	host_observation_id INTEGER NOT NULL,
	port INTEGER NOT NULL,
	protocol TEXT NOT NULL,
	state TEXT,
	service_name TEXT,
	product TEXT,
	version TEXT,
	extra_info TEXT,
	tunnel TEXT,
	UNIQUE(host_observation_id, port, protocol),
	FOREIGN KEY(host_observation_id) REFERENCES host_observations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS script_results (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	host_observation_id INTEGER,
	service_observation_id INTEGER,
	script_id TEXT NOT NULL,
	output TEXT,
	FOREIGN KEY(host_observation_id) REFERENCES host_observations(id) ON DELETE CASCADE,
	FOREIGN KEY(service_observation_id) REFERENCES service_observations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS traces (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	host_observation_id INTEGER NOT NULL,
	proto TEXT,
	port INTEGER,
	FOREIGN KEY(host_observation_id) REFERENCES host_observations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS trace_hops (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	trace_id INTEGER NOT NULL,
	ttl INTEGER NOT NULL,
	ip_address TEXT,
	rtt REAL,
	host TEXT,
	FOREIGN KEY(trace_id) REFERENCES traces(id) ON DELETE CASCADE
);
`

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
	scan_level TEXT,
	scanner_interface TEXT,
	scanner_real_mac TEXT,
	scanner_spoofed_mac TEXT,
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

CREATE TABLE IF NOT EXISTS tls_fingerprints (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	service_observation_id INTEGER NOT NULL UNIQUE,
	subject TEXT,
	issuer TEXT,
	not_before TEXT,
	not_after TEXT,
	sha256 TEXT,
	versions_json TEXT NOT NULL DEFAULT '[]',
	ciphers_json TEXT NOT NULL DEFAULT '[]',
	weak_ciphers_json TEXT NOT NULL DEFAULT '[]',
	FOREIGN KEY(service_observation_id) REFERENCES service_observations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ssh_fingerprints (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	service_observation_id INTEGER NOT NULL UNIQUE,
	host_keys_json TEXT NOT NULL DEFAULT '[]',
	algorithms_json TEXT NOT NULL DEFAULT '[]',
	weak_algorithms_json TEXT NOT NULL DEFAULT '[]',
	FOREIGN KEY(service_observation_id) REFERENCES service_observations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS http_fingerprints (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	service_observation_id INTEGER NOT NULL UNIQUE,
	title TEXT,
	server TEXT,
	methods_json TEXT NOT NULL DEFAULT '[]',
	auth_schemes_json TEXT NOT NULL DEFAULT '[]',
	paths_json TEXT NOT NULL DEFAULT '[]',
	security_headers_json TEXT NOT NULL DEFAULT '[]',
	headers_json TEXT NOT NULL DEFAULT '[]',
	FOREIGN KEY(service_observation_id) REFERENCES service_observations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS smb_fingerprints (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	service_observation_id INTEGER NOT NULL UNIQUE,
	os TEXT,
	workgroup TEXT,
	protocols_json TEXT NOT NULL DEFAULT '[]',
	shares_json TEXT NOT NULL DEFAULT '[]',
	FOREIGN KEY(service_observation_id) REFERENCES service_observations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vulnerability_findings (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	host_observation_id INTEGER,
	service_observation_id INTEGER,
	script_id TEXT NOT NULL,
	identifier TEXT,
	title TEXT,
	severity TEXT,
	state TEXT,
	evidence TEXT,
	FOREIGN KEY(host_observation_id) REFERENCES host_observations(id) ON DELETE CASCADE,
	FOREIGN KEY(service_observation_id) REFERENCES service_observations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS management_surfaces (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	host_observation_id INTEGER,
	service_observation_id INTEGER,
	category TEXT NOT NULL,
	label TEXT,
	port INTEGER NOT NULL,
	protocol TEXT NOT NULL,
	exposure TEXT,
	detail TEXT,
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

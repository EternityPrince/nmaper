package testutil

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"nmaper/internal/converter"
	"nmaper/internal/model"
	"nmaper/internal/parser"
	"nmaper/internal/scanner"
	"nmaper/internal/storage"
)

type SeededFixture struct {
	DBPath     string
	Session1ID int64
	Session2ID int64
	Target     string
	DeviceMAC  string
}

func SeedHistoryDB(t *testing.T) SeededFixture {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "nmaper.db")
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	opts := model.DefaultOptions()
	opts.Target = "10.0.0.0/24"
	opts.Save = model.SaveDB
	opts.DBPath = dbPath

	session1Start := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	session2Start := time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC)

	ctx := context.Background()
	session1ID := persistSession(t, ctx, store, opts, "session-1", session1Start, buildSession1Result(session1Start))
	session2ID := persistSession(t, ctx, store, opts, "session-2", session2Start, buildSession2Result(session2Start))

	return SeededFixture{
		DBPath:     dbPath,
		Session1ID: session1ID,
		Session2ID: session2ID,
		Target:     opts.Target,
		DeviceMAC:  "AA:BB:CC:DD:EE:FF",
	}
}

func persistSession(t *testing.T, ctx context.Context, store *storage.Store, opts model.Options, name string, startedAt time.Time, result scanner.Result) int64 {
	t.Helper()

	sessionID, err := store.BeginSession(ctx, opts, name, startedAt)
	if err != nil {
		t.Fatalf("begin session: %v", err)
	}
	if err := store.PersistCompletedSession(ctx, sessionID, opts, result); err != nil {
		t.Fatalf("persist session: %v", err)
	}
	return sessionID
}

func buildSession1Result(startedAt time.Time) scanner.Result {
	hostA := discoveryHost(
		"10.0.0.10",
		"AA:BB:CC:DD:EE:FF",
		"Acme Networks",
		[]string{"router-a.local"},
		openPort(80, "tcp", "http", "", "", "", ""),
	)
	hostB := discoveryHost(
		"10.0.0.11",
		"",
		"",
		[]string{"node-11.local"},
		openPort(8080, "tcp", "http", "", "", "", ""),
	)

	result := scanner.Result{
		SessionName:      "session-1",
		StartedAt:        startedAt,
		CompletedAt:      startedAt.Add(45 * time.Second),
		DiscoveryRun:     parser.Run{Version: "7.95", Hosts: []parser.Host{hostA, hostB}},
		DiscoveryCommand: []string{"nmap", "-sT", "10.0.0.0/24"},
		Targets: []converter.DetailTarget{
			{IP: "10.0.0.10", Ports: []int{80}},
			{IP: "10.0.0.11", Ports: []int{8080}},
		},
		DetailRuns: map[string]parser.Run{
			"10.0.0.10": {
				Version: "7.95",
				Hosts: []parser.Host{
					detailHost(
						"10.0.0.10",
						"AA:BB:CC:DD:EE:FF",
						"Acme Networks",
						[]string{"router-a.local"},
						[]parser.Port{openPort(80, "tcp", "http", "nginx", "1.25", "", "")},
						"Linux 6.x",
						[]parser.ScriptResult{{ID: "uptime", Output: "up"}},
						[]parser.ScriptResult{{ID: "http-title", Output: "Router A"}},
						true,
					),
				},
			},
			"10.0.0.11": {
				Version: "7.95",
				Hosts: []parser.Host{
					detailHost(
						"10.0.0.11",
						"",
						"",
						[]string{"node-11.local"},
						[]parser.Port{openPort(8080, "tcp", "http", "caddy", "2.8", "", "")},
						"Linux 5.x",
						nil,
						[]parser.ScriptResult{{ID: "http-title", Output: "Node 11"}},
						false,
					),
				},
			},
		},
		DetailCommands: map[string][]string{
			"10.0.0.10": {"nmap", "-A", "-p", "80", "10.0.0.10"},
			"10.0.0.11": {"nmap", "-A", "-p", "8080", "10.0.0.11"},
		},
		DetailErrors: map[string]string{},
	}
	return result
}

func buildSession2Result(startedAt time.Time) scanner.Result {
	hostA := discoveryHost(
		"10.0.0.20",
		"AA:BB:CC:DD:EE:FF",
		"Acme Networks",
		[]string{"router-b.local"},
		openPort(80, "tcp", "http", "", "", "", ""),
		openPort(443, "tcp", "https", "", "", "", "ssl"),
	)
	hostB := discoveryHost(
		"10.0.0.11",
		"",
		"",
		[]string{"node-11.local"},
		openPort(8443, "tcp", "https", "", "", "", "ssl"),
	)
	hostC := discoveryHost(
		"10.0.0.30",
		"",
		"",
		[]string{"node-30.local"},
		openPort(22, "tcp", "ssh", "", "", "", ""),
	)

	result := scanner.Result{
		SessionName:      "session-2",
		StartedAt:        startedAt,
		CompletedAt:      startedAt.Add(30 * time.Second),
		DiscoveryRun:     parser.Run{Version: "7.95", Hosts: []parser.Host{hostA, hostB, hostC}},
		DiscoveryCommand: []string{"nmap", "-sT", "10.0.0.0/24"},
		Targets: []converter.DetailTarget{
			{IP: "10.0.0.20", Ports: []int{80, 443}},
			{IP: "10.0.0.11", Ports: []int{8443}},
			{IP: "10.0.0.30", Ports: []int{22}},
		},
		DetailRuns: map[string]parser.Run{
			"10.0.0.20": {
				Version: "7.95",
				Hosts: []parser.Host{
					detailHost(
						"10.0.0.20",
						"AA:BB:CC:DD:EE:FF",
						"Acme Networks",
						[]string{"router-b.local"},
						[]parser.Port{
							openPort(80, "tcp", "http", "nginx", "1.26", "", ""),
							openPort(443, "tcp", "https", "nginx", "1.26", "", "ssl"),
						},
						"Linux 6.x",
						[]parser.ScriptResult{{ID: "uptime", Output: "up"}},
						[]parser.ScriptResult{{ID: "http-title", Output: "Router B"}},
						true,
					),
				},
			},
			"10.0.0.11": {
				Version: "7.95",
				Hosts: []parser.Host{
					detailHost(
						"10.0.0.11",
						"",
						"",
						[]string{"node-11.local"},
						[]parser.Port{openPort(8443, "tcp", "https", "caddy", "2.9", "", "ssl")},
						"Linux 5.x",
						nil,
						[]parser.ScriptResult{{ID: "http-title", Output: "Node 11 secure"}},
						false,
					),
				},
			},
			"10.0.0.30": {
				Version: "7.95",
				Hosts: []parser.Host{
					detailHost(
						"10.0.0.30",
						"",
						"",
						[]string{"node-30.local"},
						[]parser.Port{openPort(22, "tcp", "ssh", "OpenSSH", "9.9", "", "")},
						"OpenBSD",
						nil,
						nil,
						false,
					),
				},
			},
		},
		DetailCommands: map[string][]string{
			"10.0.0.20": {"nmap", "-A", "-p", "80,443", "10.0.0.20"},
			"10.0.0.11": {"nmap", "-A", "-p", "8443", "10.0.0.11"},
			"10.0.0.30": {"nmap", "-A", "-p", "22", "10.0.0.30"},
		},
		DetailErrors: map[string]string{},
	}
	return result
}

func discoveryHost(ip, mac, vendor string, hostnames []string, ports ...parser.Port) parser.Host {
	return parser.Host{
		Status:    "up",
		Addresses: addresses(ip, mac, vendor),
		Hostnames: hostnames,
		Ports:     ports,
	}
}

func detailHost(ip, mac, vendor string, hostnames []string, ports []parser.Port, topOS string, hostScripts []parser.ScriptResult, portScripts []parser.ScriptResult, withTrace bool) parser.Host {
	for index := range ports {
		if len(portScripts) > 0 {
			ports[index].Scripts = append([]parser.ScriptResult(nil), portScripts...)
		}
	}
	host := parser.Host{
		Status:    "up",
		Addresses: addresses(ip, mac, vendor),
		Hostnames: hostnames,
		Ports:     ports,
		Scripts:   append([]parser.ScriptResult(nil), hostScripts...),
	}
	if topOS != "" {
		host.OSMatches = []parser.OSMatch{{Name: topOS, Accuracy: 99, Classes: []string{topOS}}}
	}
	if withTrace {
		host.Trace = &parser.Trace{
			Proto: "tcp",
			Port:  ports[0].ID,
			Hops: []parser.TraceHop{
				{TTL: 1, IP: "10.0.0.1", RTT: 0.91, Host: "gateway"},
			},
		}
	}
	return host
}

func addresses(ip, mac, vendor string) []parser.Address {
	out := []parser.Address{{Type: "ipv4", Addr: ip}}
	if mac != "" {
		out = append(out, parser.Address{Type: "mac", Addr: mac, Vendor: vendor})
	}
	return out
}

func openPort(port int, protocol, serviceName, product, version, extraInfo, tunnel string) parser.Port {
	return parser.Port{
		ID:       port,
		Protocol: protocol,
		State:    "open",
		Service: parser.Service{
			Name:      serviceName,
			Product:   product,
			Version:   version,
			ExtraInfo: extraInfo,
			Tunnel:    tunnel,
		},
	}
}

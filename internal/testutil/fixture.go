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
	if err := store.PersistCompletedSession(ctx, sessionID, opts, completedScan(result)); err != nil {
		t.Fatalf("persist session: %v", err)
	}
	return sessionID
}

func completedScan(result scanner.Result) storage.CompletedScan {
	return storage.CompletedScan{
		SessionName: result.SessionName,
		StartedAt:   result.StartedAt,
		CompletedAt: result.CompletedAt,
		SourceIdentity: storage.SourceIdentity{
			Interface:  result.SourceIdentity.Interface,
			RealMAC:    result.SourceIdentity.RealMAC,
			SpoofedMAC: result.SourceIdentity.SpoofedMAC,
		},
		DiscoveryRun:     result.DiscoveryRun,
		DiscoveryCommand: append([]string(nil), result.DiscoveryCommand...),
		DetailRuns:       cloneDetailRuns(result.DetailRuns),
		DetailCommands:   cloneDetailCommands(result.DetailCommands),
		DetailErrors:     cloneDetailErrors(result.DetailErrors),
		Targets:          cloneTargets(result.Targets),
	}
}

func cloneDetailRuns(source map[string]parser.Run) map[string]parser.Run {
	if len(source) == 0 {
		return nil
	}
	cloned := make(map[string]parser.Run, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func cloneDetailCommands(source map[string][]string) map[string][]string {
	if len(source) == 0 {
		return nil
	}
	cloned := make(map[string][]string, len(source))
	for key, value := range source {
		cloned[key] = append([]string(nil), value...)
	}
	return cloned
}

func cloneDetailErrors(source map[string]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func cloneTargets(source []converter.DetailTarget) []converter.DetailTarget {
	if len(source) == 0 {
		return nil
	}
	cloned := make([]converter.DetailTarget, 0, len(source))
	for _, target := range source {
		cloned = append(cloned, converter.DetailTarget{
			IP:    target.IP,
			Ports: append([]int(nil), target.Ports...),
		})
	}
	return cloned
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
						[]parser.Port{
							withScripts(
								openPort(80, "tcp", "http", "nginx", "1.25", "", ""),
								parser.ScriptResult{ID: "http-title", Output: "Router A"},
								parser.ScriptResult{ID: "http-headers", Output: "Server: nginx\nStrict-Transport-Security: max-age=63072000"},
							),
						},
						"Linux 6.x",
						[]parser.ScriptResult{{ID: "uptime", Output: "up"}},
						nil,
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
						[]parser.Port{
							withScripts(
								openPort(8080, "tcp", "http", "caddy", "2.8", "", ""),
								parser.ScriptResult{ID: "http-title", Output: "Node 11"},
								parser.ScriptResult{ID: "http-methods", Output: "Supported Methods: GET HEAD POST"},
							),
						},
						"Linux 5.x",
						nil,
						nil,
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
							withScripts(
								openPort(80, "tcp", "http", "nginx", "1.26", "", ""),
								parser.ScriptResult{ID: "http-title", Output: "Router B"},
								parser.ScriptResult{ID: "http-headers", Output: "Server: nginx\nStrict-Transport-Security: max-age=63072000"},
							),
							withScripts(
								openPort(443, "tcp", "https", "nginx", "1.26", "", "ssl"),
								parser.ScriptResult{ID: "ssl-cert", Output: "Subject: CN=router-b.local\nIssuer: CN=Acme Root\nSHA256: AA:BB:CC:DD"},
								parser.ScriptResult{ID: "ssl-enum-ciphers", Output: "TLSv1.2:\n  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n  TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
								parser.ScriptResult{ID: "ssl-heartbleed", Output: "NOT VULNERABLE"},
							),
						},
						"Linux 6.x",
						[]parser.ScriptResult{{ID: "uptime", Output: "up"}},
						nil,
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
						[]parser.Port{
							withScripts(
								openPort(8443, "tcp", "https", "caddy", "2.9", "", "ssl"),
								parser.ScriptResult{ID: "http-title", Output: "Node 11 secure"},
								parser.ScriptResult{ID: "http-auth", Output: "Basic realm=secure"},
								parser.ScriptResult{ID: "ssl-cert", Output: "Subject: CN=node-11.local\nIssuer: CN=Lab Root\nSHA256: 11:22:33:44"},
							),
						},
						"Linux 5.x",
						nil,
						nil,
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
						[]parser.Port{
							withScripts(
								openPort(22, "tcp", "ssh", "OpenSSH", "9.9", "", ""),
								parser.ScriptResult{ID: "ssh-hostkey", Output: "3072 aa:bb:cc ssh-rsa"},
								parser.ScriptResult{ID: "ssh2-enum-algos", Output: "curve25519-sha256\ndiffie-hellman-group1-sha1"},
							),
						},
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

func withScripts(port parser.Port, scripts ...parser.ScriptResult) parser.Port {
	port.Scripts = append([]parser.ScriptResult(nil), scripts...)
	return port
}

package history

import "testing"

func TestAlertsFromChangedHost(t *testing.T) {
	t.Parallel()

	host := ChangedHost{
		IP:          "10.0.0.50",
		After:       HostDiffSnapshot{IP: "10.0.0.50"},
		OpenedPorts: []string{"3389/tcp", "8443/tcp"},
		ScriptChanges: []ScriptDelta{
			{Scope: "443/tcp", ID: "ssl-cert", Before: "CN=old.example", After: "CN=new.example"},
			{Scope: "22/tcp", ID: "ssh-hostkey", Before: "ecdsa-sha2 old", After: "ecdsa-sha2 new"},
			{Scope: "8443/tcp", ID: "http-title", Before: "Old Console", After: "New Console"},
		},
	}

	alerts := alertsFromChangedHost(host)
	if len(alerts) != 5 {
		t.Fatalf("expected 5 alerts, got %#v", alerts)
	}
	if !hasAlertType(alerts, "rdp_appeared") {
		t.Fatalf("expected rdp alert, got %#v", alerts)
	}
	if !hasAlertType(alerts, "management_port_opened") {
		t.Fatalf("expected management-port alert, got %#v", alerts)
	}
	if !hasAlertType(alerts, "tls_certificate_changed") {
		t.Fatalf("expected tls alert, got %#v", alerts)
	}
	if !hasAlertType(alerts, "ssh_hostkey_rotated") {
		t.Fatalf("expected ssh-hostkey alert, got %#v", alerts)
	}
	if !hasAlertType(alerts, "http_title_changed") {
		t.Fatalf("expected http-title alert, got %#v", alerts)
	}
}

func hasAlertType(items []DiffAlert, want string) bool {
	for _, item := range items {
		if item.Type == want {
			return true
		}
	}
	return false
}

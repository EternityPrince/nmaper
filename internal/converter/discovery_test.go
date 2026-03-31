package converter

import (
	"reflect"
	"testing"

	"nmaper/internal/parser"
)

func TestDiscoveryToDetailTargets(t *testing.T) {
	t.Parallel()

	run := parser.Run{
		Hosts: []parser.Host{
			{
				Addresses: []parser.Address{{Type: "ipv4", Addr: "10.0.0.20"}},
				Ports: []parser.Port{
					{ID: 443, Protocol: "tcp", State: "open"},
					{ID: 53, Protocol: "udp", State: "closed"},
					{ID: 80, Protocol: "tcp", State: "open"},
				},
			},
			{
				Addresses: []parser.Address{{Type: "ipv4", Addr: "10.0.0.10"}},
				Ports: []parser.Port{
					{ID: 22, Protocol: "tcp", State: "open"},
				},
			},
			{
				Addresses: []parser.Address{{Type: "ipv4", Addr: "10.0.0.30"}},
				Ports: []parser.Port{
					{ID: 25, Protocol: "tcp", State: "closed"},
				},
			},
			{
				Status:    "up",
				Addresses: []parser.Address{{Type: "ipv4", Addr: "10.0.0.40"}},
			},
		},
	}

	got := DiscoveryToDetailTargets(run)
	want := []DetailTarget{
		{IP: "10.0.0.10", Ports: []int{22}},
		{IP: "10.0.0.20", Ports: []int{80, 443}},
		{IP: "10.0.0.40", Ports: []int{}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected targets:\nwant %#v\ngot  %#v", want, got)
	}
}

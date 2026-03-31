package scanner

import (
	"reflect"
	"testing"

	"nmaper/internal/model"
)

func TestBuildDiscoveryArgs(t *testing.T) {
	t.Parallel()

	opts := model.DefaultOptions()
	opts.Target = "192.168.1.0/24"
	opts.UseSudo = true
	opts.NoPing = true
	opts.TopPorts = 100
	opts.Timing = 3

	want := []string{"-sS", "192.168.1.0/24", "-T", "3", "-oX", "-", "-Pn", "--top-ports", "100"}
	if got := BuildDiscoveryArgs(opts); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected discovery args:\nwant %#v\ngot  %#v", want, got)
	}
}

func TestBuildDetailArgsDefaultAndSelective(t *testing.T) {
	t.Parallel()

	opts := model.DefaultOptions()
	opts.Timing = 4
	wantDefault := []string{"-T", "4", "-oX", "-", "-p", "22,80", "-A", "192.168.1.10"}
	if got := BuildDetailArgs("192.168.1.10", []int{22, 80}, opts); !reflect.DeepEqual(got, wantDefault) {
		t.Fatalf("unexpected default detail args:\nwant %#v\ngot  %#v", wantDefault, got)
	}

	opts.ServiceVersion = true
	opts.OSDetect = false
	wantSelective := []string{"-T", "4", "-oX", "-", "-p", "22,80", "-sV", "192.168.1.10"}
	if got := BuildDetailArgs("192.168.1.10", []int{22, 80}, opts); !reflect.DeepEqual(got, wantSelective) {
		t.Fatalf("unexpected selective detail args:\nwant %#v\ngot  %#v", wantSelective, got)
	}
}

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"nmaper/internal/history"
	"nmaper/internal/testutil"
)

func TestRunHelpAndInvalidArgs(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Run(context.Background(), []string{"--help"}, bytes.NewBuffer(nil), &stdout, &stderr); code != 0 {
		t.Fatalf("expected help exit code 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("expected usage output, got: %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(context.Background(), []string{"--unknown-flag"}, bytes.NewBuffer(nil), &stdout, &stderr); code != 2 {
		t.Fatalf("expected parse error exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "unknown flag") {
		t.Fatalf("expected parse error in stderr, got: %q", stderr.String())
	}
}

func TestRunSessionsMode(t *testing.T) {
	t.Parallel()

	fixture := testutil.SeedHistoryDB(t)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run(
		context.Background(),
		[]string{"--sessions", "--db", fixture.DBPath, "--out", "json"},
		bytes.NewBuffer(nil),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected sessions mode to succeed, code=%d stderr=%s", code, stderr.String())
	}

	var sessions []history.SessionSummary
	if err := json.Unmarshal(stdout.Bytes(), &sessions); err != nil {
		t.Fatalf("unmarshal sessions: %v\n%s", err, stdout.String())
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
}

func TestRunHistoryModes(t *testing.T) {
	t.Parallel()

	fixture := testutil.SeedHistoryDB(t)
	cases := []struct {
		name  string
		args  []string
		match string
	}{
		{"session", []string{"--session", strconv.FormatInt(fixture.Session1ID, 10), "--db", fixture.DBPath, "--out", "json"}, "\"hosts\""},
		{"diff", []string{"--diff", strconv.FormatInt(fixture.Session1ID, 10), strconv.FormatInt(fixture.Session2ID, 10), "--db", fixture.DBPath, "--out", "json"}, "\"changed_hosts\""},
		{"diff-global", []string{"--diff-global", "--db", fixture.DBPath, "--out", "json"}, "\"session_count\""},
		{"devices", []string{"--devices", "--db", fixture.DBPath, "--out", "json"}, "\"unique_devices\""},
		{"device", []string{"--device", "acme", "--db", fixture.DBPath, "--out", "json"}, "\"appearances\""},
		{"timeline", []string{"--timeline", "--db", fixture.DBPath, "--out", "json"}, "\"entries\""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := Run(context.Background(), tc.args, bytes.NewBuffer(nil), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("Run failed: code=%d stderr=%s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.match) {
				t.Fatalf("expected %q in output, got: %s", tc.match, stdout.String())
			}
		})
	}
}

func TestConfirmDeletionRequiresTTY(t *testing.T) {
	t.Parallel()

	confirmed, err := confirmDeletion(bytes.NewBufferString("y\n"), &bytes.Buffer{}, 12)
	if err == nil || confirmed {
		t.Fatalf("expected TTY guard failure, confirmed=%v err=%v", confirmed, err)
	}
}

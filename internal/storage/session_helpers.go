package storage

import (
	"sort"
	"strings"

	"nmaper/internal/parser"
)

func mergeHost(discovery parser.Host, detail parser.Host) parser.Host {
	merged := detail
	if merged.Status == "" {
		merged.Status = discovery.Status
	}
	if len(merged.Addresses) == 0 {
		merged.Addresses = discovery.Addresses
	}
	if len(merged.Hostnames) == 0 {
		merged.Hostnames = discovery.Hostnames
	}
	if len(merged.OSMatches) == 0 {
		merged.OSMatches = discovery.OSMatches
	}
	if len(merged.Ports) == 0 {
		merged.Ports = discovery.Ports
	}
	if merged.Trace == nil {
		merged.Trace = discovery.Trace
	}
	if len(merged.Scripts) == 0 {
		merged.Scripts = discovery.Scripts
	}
	return merged
}

func firstDetailCommand(commands map[string][]string) string {
	if len(commands) == 0 {
		return ""
	}
	keys := make([]string, 0, len(commands))
	for key := range commands {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(commands[keys[0]], " ")
}

func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableInt64(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

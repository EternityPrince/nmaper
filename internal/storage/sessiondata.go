package storage

import (
	"time"

	"nmaper/internal/converter"
	"nmaper/internal/parser"
)

type SourceIdentity struct {
	Interface  string
	RealMAC    string
	SpoofedMAC string
}

type CompletedScan struct {
	SessionName      string
	StartedAt        time.Time
	CompletedAt      time.Time
	SourceIdentity   SourceIdentity
	DiscoveryRun     parser.Run
	DiscoveryCommand []string
	DetailRuns       map[string]parser.Run
	DetailCommands   map[string][]string
	DetailErrors     map[string]string
	Targets          []converter.DetailTarget
}

package app

import (
	"context"
	"time"

	"nmaper/internal/converter"
	"nmaper/internal/history"
	"nmaper/internal/model"
	"nmaper/internal/parser"
	"nmaper/internal/scanner"
	"nmaper/internal/storage"
	"nmaper/internal/termui"
)

type scanRunner interface {
	EnsureReady(context.Context, model.Options) error
	ResolveSourceIdentity(string, string) (scanner.SourceIdentity, error)
	Run(context.Context, model.Options) (scanner.Result, error)
}

type sessionStore interface {
	Close() error
	BeginSession(context.Context, model.Options, string, time.Time) (int64, error)
	AttachSourceIdentity(context.Context, int64, storage.SourceIdentity) error
	MarkSessionFailed(context.Context, int64, error) error
	PersistCompletedSession(context.Context, int64, model.Options, storage.CompletedScan) error
	DeleteAll(context.Context) error
	DeleteSession(context.Context, int64) error
}

type historyService interface {
	ListSessions(context.Context, int, string, string) ([]history.SessionSummary, error)
	SessionReport(context.Context, int64, string) (history.SessionReport, error)
	Diff(context.Context, int64, int64) (history.DiffReport, error)
	GlobalDynamics(context.Context, int, string, string) (history.GlobalDynamicsReport, error)
	Devices(context.Context, string, bool, bool) (history.DeviceAnalyticsReport, error)
	DeviceHistory(context.Context, string, string, bool, bool) (history.DeviceHistoryReport, error)
	Timeline(context.Context, int, string, string) (history.TimelineReport, error)
}

func newScanRunner(log *termui.Logger) scanRunner {
	return scanner.New(log)
}

func openStore(path string) (sessionStore, error) {
	return storage.Open(path)
}

func openHistory(path string) (historyService, func(), error) {
	store, err := storage.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return history.New(store.DB()), func() { _ = store.Close() }, nil
}

func toStorageSourceIdentity(identity scanner.SourceIdentity) storage.SourceIdentity {
	return storage.SourceIdentity{
		Interface:  identity.Interface,
		RealMAC:    identity.RealMAC,
		SpoofedMAC: identity.SpoofedMAC,
	}
}

func toCompletedScan(result scanner.Result) storage.CompletedScan {
	return storage.CompletedScan{
		SessionName:      result.SessionName,
		StartedAt:        result.StartedAt,
		CompletedAt:      result.CompletedAt,
		SourceIdentity:   toStorageSourceIdentity(result.SourceIdentity),
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

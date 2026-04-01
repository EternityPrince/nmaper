package app

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"nmaper/internal/model"
	"nmaper/internal/scanner"
	"nmaper/internal/termui"
)

func runScan(ctx context.Context, opts model.Options, stdout io.Writer, logger *termui.Logger) int {
	normalized, err := model.NormalizeScanOptions(opts)
	if err != nil {
		logger.Failf("%v", err)
		return 1
	}
	opts = normalized

	if opts.Name == "" {
		opts.Name = scanner.SessionName(opts)
	}
	logger.Phasef("scan level %s selected: %s", opts.Level, model.ScanLevelSummary(opts))

	sc := newScanRunner(logger)
	if err := sc.EnsureReady(ctx, opts); err != nil {
		logger.Failf("%v", err)
		return 1
	}
	sourceIdentity, err := sc.ResolveSourceIdentity(opts.Target, opts.SpoofMAC)
	if err != nil {
		logger.Failf("resolve source identity: %v", err)
		return 1
	}
	if sourceIdentity.SpoofedMAC != "" {
		opts.SpoofMAC = sourceIdentity.SpoofedMAC
	}

	var (
		store     sessionStore
		sessionID int64
	)
	if opts.Save == model.SaveDB {
		store, err = openStore(opts.DBPath)
		if err != nil {
			logger.Failf("open database: %v", err)
			return 1
		}
		defer store.Close()

		sessionID, err = store.BeginSession(ctx, opts, opts.Name, time.Now())
		if err != nil {
			logger.Failf("create running session: %v", err)
			return 1
		}
		if err := store.AttachSourceIdentity(ctx, sessionID, toStorageSourceIdentity(sourceIdentity)); err != nil {
			logger.Failf("attach source identity: %v", err)
			return 1
		}
	}

	result, runErr := sc.Run(ctx, opts)
	if runErr != nil {
		if store != nil && sessionID > 0 {
			_ = store.MarkSessionFailed(ctx, sessionID, runErr)
		}
		logger.Failf("%v", runErr)
		return 1
	}

	if store != nil && sessionID > 0 {
		if err := store.PersistCompletedSession(ctx, sessionID, opts, toCompletedScan(result)); err != nil {
			_ = store.MarkSessionFailed(ctx, sessionID, err)
			logger.Failf("persist session: %v", err)
			return 1
		}
	}

	fmt.Fprintf(stdout, "Session: %s\n", result.SessionName)
	if sessionID > 0 {
		fmt.Fprintf(stdout, "Session ID: %d\n", sessionID)
	}
	fmt.Fprintf(stdout, "Scan level: %s\n", opts.Level)
	fmt.Fprintf(stdout, "Profile: %s\n", model.ScanLevelSummary(opts))
	fmt.Fprintf(stdout, "Enabled: %s\n", strings.Join(model.ScanLevelCapabilities(opts), ", "))
	fmt.Fprintf(stdout, "Target: %s\n", opts.Target)
	fmt.Fprintf(stdout, "Discovered hosts: %d\n", len(result.DiscoveryRun.Hosts))
	fmt.Fprintf(stdout, "Live hosts: %d\n", len(result.Targets))
	fmt.Fprintf(stdout, "Detail scans: %d\n", len(result.DetailRuns))
	fmt.Fprintf(stdout, "Detail errors: %d\n", len(result.DetailErrors))
	fmt.Fprintf(stdout, "Duration: %s\n", result.CompletedAt.Sub(result.StartedAt))
	if result.SourceIdentity.Interface != "" {
		fmt.Fprintf(stdout, "Scanner interface: %s\n", result.SourceIdentity.Interface)
	}
	if result.SourceIdentity.RealMAC != "" {
		fmt.Fprintf(stdout, "Scanner real MAC: %s\n", result.SourceIdentity.RealMAC)
	}
	if result.SourceIdentity.SpoofedMAC != "" {
		fmt.Fprintf(stdout, "Scanner spoofed MAC: %s\n", result.SourceIdentity.SpoofedMAC)
	}
	if opts.Save == model.SaveXML {
		fmt.Fprintf(stdout, "XML output: %s/%s/xml\n", opts.OutputDir, result.SessionName)
	}
	return 0
}

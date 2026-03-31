package app

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"nmaper/internal/cli"
	"nmaper/internal/history"
	"nmaper/internal/model"
	"nmaper/internal/output"
	"nmaper/internal/preflight"
	"nmaper/internal/scanner"
	"nmaper/internal/storage"
	"nmaper/internal/termui"
)

func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts, err := cli.Parse(args)
	if err != nil {
		if cli.IsHelp(err) {
			fmt.Fprintln(stdout, cli.Usage())
			return 0
		}
		fmt.Fprintf(stderr, "%v\n\n%s\n", err, cli.Usage())
		return 2
	}
	if opts.ShowHelp {
		fmt.Fprintln(stdout, cli.Usage())
		return 0
	}

	logger := termui.New(stderr, opts.Verbose)
	wd, _ := os.Getwd()
	if opts.Dev || opts.Check {
		logger.Phasef("running preflight checks")
		if err := preflight.Run(ctx, wd); err != nil {
			logger.Failf("preflight failed: %v", err)
			return 1
		}
		logger.OKf("preflight passed")
		if opts.Check {
			return 0
		}
	}

	switch opts.Mode {
	case model.ModeScan:
		return runScan(ctx, opts, stdout, logger)
	case model.ModeSessions:
		return runSessions(ctx, opts, stdout, logger)
	case model.ModeSession:
		if opts.DeleteTarget != nil {
			return runDelete(ctx, opts, stdin, stdout, logger)
		}
		return runSession(ctx, opts, stdout, logger)
	case model.ModeDiff:
		return runDiff(ctx, opts, stdout, logger)
	case model.ModeDiffGlobal:
		return runGlobal(ctx, opts, stdout, logger)
	case model.ModeDevices:
		return runDevices(ctx, opts, stdout, logger)
	case model.ModeDevice:
		return runDevice(ctx, opts, stdout, logger)
	case model.ModeTimeline:
		return runTimeline(ctx, opts, stdout, logger)
	case model.ModeCheck:
		return 0
	default:
		fmt.Fprintf(stderr, "unsupported mode %q\n", opts.Mode)
		return 2
	}
}

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

	sc := scanner.New(logger)
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
		store     *storage.Store
		sessionID int64
	)
	if opts.Save == model.SaveDB {
		store, err = storage.Open(opts.DBPath)
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
		if err := store.AttachSourceIdentity(ctx, sessionID, sourceIdentity); err != nil {
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
		if err := store.PersistCompletedSession(ctx, sessionID, opts, result); err != nil {
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

func runSessions(ctx context.Context, opts model.Options, stdout io.Writer, logger *termui.Logger) int {
	service, cleanup, err := openHistory(opts)
	if err != nil {
		logger.Failf("open database: %v", err)
		return 1
	}
	defer cleanup()

	report, err := service.ListSessions(ctx, opts.Limit, opts.Status, opts.TargetFilter)
	if err != nil {
		logger.Failf("list sessions: %v", err)
		return 1
	}
	body, err := output.RenderSessions(report, opts.Out)
	if err != nil {
		logger.Failf("render sessions: %v", err)
		return 1
	}
	if err := output.Emit(body, opts.Out, stdout, logger); err != nil {
		logger.Failf("emit sessions: %v", err)
		return 1
	}
	return 0
}

func runSession(ctx context.Context, opts model.Options, stdout io.Writer, logger *termui.Logger) int {
	service, cleanup, err := openHistory(opts)
	if err != nil {
		logger.Failf("open database: %v", err)
		return 1
	}
	defer cleanup()

	report, err := service.SessionReport(ctx, *opts.SessionID, opts.HostQuery)
	if err != nil {
		logger.Failf("load session: %v", err)
		return 1
	}
	body, err := output.RenderSession(report, opts.Out)
	if err != nil {
		logger.Failf("render session: %v", err)
		return 1
	}
	if err := output.Emit(body, opts.Out, stdout, logger); err != nil {
		logger.Failf("emit session: %v", err)
		return 1
	}
	return 0
}

func runDiff(ctx context.Context, opts model.Options, stdout io.Writer, logger *termui.Logger) int {
	service, cleanup, err := openHistory(opts)
	if err != nil {
		logger.Failf("open database: %v", err)
		return 1
	}
	defer cleanup()

	report, err := service.Diff(ctx, opts.DiffIDs[0], opts.DiffIDs[1])
	if err != nil {
		logger.Failf("build diff: %v", err)
		return 1
	}
	body, err := output.RenderDiff(report, opts.Out)
	if err != nil {
		logger.Failf("render diff: %v", err)
		return 1
	}
	if err := output.Emit(body, opts.Out, stdout, logger); err != nil {
		logger.Failf("emit diff: %v", err)
		return 1
	}
	return 0
}

func runGlobal(ctx context.Context, opts model.Options, stdout io.Writer, logger *termui.Logger) int {
	service, cleanup, err := openHistory(opts)
	if err != nil {
		logger.Failf("open database: %v", err)
		return 1
	}
	defer cleanup()

	report, err := service.GlobalDynamics(ctx, opts.Limit, opts.Status, opts.TargetFilter)
	if err != nil {
		logger.Failf("build global dynamics: %v", err)
		return 1
	}
	body, err := output.RenderGlobal(report, opts.Out)
	if err != nil {
		logger.Failf("render global dynamics: %v", err)
		return 1
	}
	if err := output.Emit(body, opts.Out, stdout, logger); err != nil {
		logger.Failf("emit global dynamics: %v", err)
		return 1
	}
	return 0
}

func runDevices(ctx context.Context, opts model.Options, stdout io.Writer, logger *termui.Logger) int {
	service, cleanup, err := openHistory(opts)
	if err != nil {
		logger.Failf("open database: %v", err)
		return 1
	}
	defer cleanup()

	report, err := service.Devices(ctx, opts.Vendor, opts.MACOnly, opts.IPOnly)
	if err != nil {
		logger.Failf("build devices analytics: %v", err)
		return 1
	}
	body, err := output.RenderDevices(report, opts.Out)
	if err != nil {
		logger.Failf("render devices analytics: %v", err)
		return 1
	}
	if err := output.Emit(body, opts.Out, stdout, logger); err != nil {
		logger.Failf("emit devices analytics: %v", err)
		return 1
	}
	return 0
}

func runDevice(ctx context.Context, opts model.Options, stdout io.Writer, logger *termui.Logger) int {
	service, cleanup, err := openHistory(opts)
	if err != nil {
		logger.Failf("open database: %v", err)
		return 1
	}
	defer cleanup()

	report, err := service.DeviceHistory(ctx, opts.DeviceQuery, opts.Vendor, opts.MACOnly, opts.IPOnly)
	if err != nil {
		logger.Failf("load device history: %v", err)
		return 1
	}
	body, err := output.RenderDeviceHistory(report, opts.Out)
	if err != nil {
		logger.Failf("render device history: %v", err)
		return 1
	}
	if err := output.Emit(body, opts.Out, stdout, logger); err != nil {
		logger.Failf("emit device history: %v", err)
		return 1
	}
	return 0
}

func runTimeline(ctx context.Context, opts model.Options, stdout io.Writer, logger *termui.Logger) int {
	service, cleanup, err := openHistory(opts)
	if err != nil {
		logger.Failf("open database: %v", err)
		return 1
	}
	defer cleanup()

	report, err := service.Timeline(ctx, opts.Limit, opts.Status, opts.TargetFilter)
	if err != nil {
		logger.Failf("build timeline: %v", err)
		return 1
	}
	body, err := output.RenderTimeline(report, opts.Out)
	if err != nil {
		logger.Failf("render timeline: %v", err)
		return 1
	}
	if err := output.Emit(body, opts.Out, stdout, logger); err != nil {
		logger.Failf("emit timeline: %v", err)
		return 1
	}
	return 0
}

func runDelete(ctx context.Context, opts model.Options, stdin io.Reader, stdout io.Writer, logger *termui.Logger) int {
	store, err := storage.Open(opts.DBPath)
	if err != nil {
		logger.Failf("open database: %v", err)
		return 1
	}
	defer store.Close()

	confirmed, err := confirmDeletion(stdin, stdout, *opts.DeleteTarget)
	if err != nil {
		logger.Failf("%v", err)
		return 1
	}
	if !confirmed {
		fmt.Fprintln(stdout, "Deletion cancelled.")
		return 0
	}

	if *opts.DeleteTarget == -1 {
		if err := store.DeleteAll(ctx); err != nil {
			logger.Failf("delete all sessions: %v", err)
			return 1
		}
		fmt.Fprintln(stdout, "All sessions deleted.")
		return 0
	}

	if err := store.DeleteSession(ctx, *opts.DeleteTarget); err != nil {
		logger.Failf("delete session: %v", err)
		return 1
	}
	fmt.Fprintf(stdout, "Session %d deleted.\n", *opts.DeleteTarget)
	return 0
}

func openHistory(opts model.Options) (*history.Service, func(), error) {
	store, err := storage.Open(opts.DBPath)
	if err != nil {
		return nil, nil, err
	}
	return history.New(store.DB()), func() { _ = store.Close() }, nil
}

func confirmDeletion(stdin io.Reader, stdout io.Writer, deleteTarget int64) (bool, error) {
	if !isTTY(stdin) || !isTTYWriter(stdout) {
		return false, fmt.Errorf("delete requires an interactive TTY")
	}
	prompt := fmt.Sprintf("Delete session %d? [y/N]: ", deleteTarget)
	if deleteTarget == -1 {
		prompt = "Delete all sessions? [y/N]: "
	}
	if _, err := fmt.Fprint(stdout, prompt); err != nil {
		return false, err
	}
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(line), "y"), nil
}

func isTTY(reader io.Reader) bool {
	file, ok := reader.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func isTTYWriter(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

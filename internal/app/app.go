package app

import (
	"context"
	"fmt"
	"io"
	"os"

	"nmaper/internal/cli"
	"nmaper/internal/model"
	"nmaper/internal/preflight"
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

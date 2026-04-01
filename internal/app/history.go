package app

import (
	"context"
	"io"

	"nmaper/internal/model"
	"nmaper/internal/output"
	"nmaper/internal/termui"
)

func runSessions(ctx context.Context, opts model.Options, stdout io.Writer, logger *termui.Logger) int {
	service, cleanup, err := openHistory(opts.DBPath)
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
	body, err := output.RenderSessionsView(report, opts.Out, opts.View)
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
	service, cleanup, err := openHistory(opts.DBPath)
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
	body, err := output.RenderSessionView(report, opts.Out, opts.View)
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
	service, cleanup, err := openHistory(opts.DBPath)
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
	body, err := output.RenderDiffView(report, opts.Out, opts.View)
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
	service, cleanup, err := openHistory(opts.DBPath)
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
	body, err := output.RenderGlobalView(report, opts.Out, opts.View)
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
	service, cleanup, err := openHistory(opts.DBPath)
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
	body, err := output.RenderDevicesView(report, opts.Out, opts.View)
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
	service, cleanup, err := openHistory(opts.DBPath)
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
	body, err := output.RenderDeviceHistoryView(report, opts.Out, opts.View)
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
	service, cleanup, err := openHistory(opts.DBPath)
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
	body, err := output.RenderTimelineView(report, opts.Out, opts.View)
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

func runPosture(ctx context.Context, opts model.Options, stdout io.Writer, logger *termui.Logger) int {
	service, cleanup, err := openHistory(opts.DBPath)
	if err != nil {
		logger.Failf("open database: %v", err)
		return 1
	}
	defer cleanup()

	report, err := service.Posture(ctx, opts.Vendor, opts.Network)
	if err != nil {
		logger.Failf("build posture summary: %v", err)
		return 1
	}
	body, err := output.RenderPostureView(report, opts.Out, opts.View)
	if err != nil {
		logger.Failf("render posture summary: %v", err)
		return 1
	}
	if err := output.Emit(body, opts.Out, stdout, logger); err != nil {
		logger.Failf("emit posture summary: %v", err)
		return 1
	}
	return 0
}

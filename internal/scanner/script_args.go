package scanner

import (
	"fmt"
	"strings"

	"nmaper/internal/model"
	"nmaper/internal/parser"
)

func BuildPortProbeArgs(ip string, opts model.Options) []string {
	opts = effectiveOptions(opts)
	opts = detailPhaseOptions(ip, opts)

	args := []string{
		tcpScanFlag(opts),
		"-T", fmt.Sprintf("%d", opts.Timing),
		"-oX", "-",
	}
	switch {
	case opts.Ports != "":
		args = append(args, "-p", opts.Ports)
	case opts.TopPorts > 0:
		args = append(args, "--top-ports", fmt.Sprintf("%d", opts.TopPorts))
	}
	args = append(args, "-Pn")
	if opts.ServiceVersion {
		args = append(args, "-sV")
	}
	if opts.SpoofMAC != "" {
		args = append(args, "--spoof-mac", opts.SpoofMAC)
	}
	args = append(args, ip)
	return args
}

func BuildDetailArgsForHost(ip string, ports []int, host parser.Host, opts model.Options) []string {
	opts = effectiveOptions(opts)
	opts = detailPhaseOptions(ip, opts)
	return buildDetailArgs(detailContextForHost(ip, ports, host, opts), opts)
}

func RecommendedScripts(ports []int) []string {
	return effectiveRecommendedScripts(detailProfileContext{
		Level:    model.ScanLevelHigh,
		TCPPorts: ports,
		UDPPorts: defaultUDPPorts,
	})
}

func RecommendedScriptsForHost(ip string, ports []int, host parser.Host) []string {
	return effectiveRecommendedScripts(detailContextForHost(ip, ports, host, model.Options{
		Level:     model.ScanLevelHigh,
		UseSudo:   true,
		EnableUDP: true,
	}))
}

func buildDetailArgs(ctx detailProfileContext, opts model.Options) []string {
	args := []string{
		tcpScanFlag(opts),
		"-T", fmt.Sprintf("%d", opts.Timing),
		"-oX", "-",
	}
	udpPorts := append([]int(nil), ctx.UDPPorts...)
	switch {
	case len(ctx.TCPPorts) > 0:
		args = append(args, "-p", joinProtocolPorts(ctx.TCPPorts, udpPorts))
	case opts.Ports != "":
		udpPorts = nil
		args = append(args, "-p", opts.Ports)
	case opts.TopPorts > 0:
		udpPorts = nil
		args = append(args, "--top-ports", fmt.Sprintf("%d", opts.TopPorts))
	}
	if len(udpPorts) > 0 {
		args = append(args, "-sU", "--version-light")
	}
	if opts.ServiceVersion {
		args = append(args, "-sV")
	}
	if opts.OSDetect {
		args = append(args, "-O")
	}
	if opts.EnableTraceroute && opts.UseSudo {
		args = append(args, "--traceroute")
	}
	args = append(args, "-Pn")
	if opts.SpoofMAC != "" {
		args = append(args, "--spoof-mac", opts.SpoofMAC)
	}
	ctx.UDPPorts = udpPorts
	if scripts := effectiveDetailScripts(ctx); len(scripts) > 0 {
		args = append(args, "--script", strings.Join(scripts, ","))
	}
	args = append(args, ctx.IP)
	return args
}

func detailUDPPorts(opts model.Options) []int {
	if !opts.UseSudo || !opts.EnableUDP {
		return nil
	}
	return append([]int(nil), defaultUDPPorts...)
}

func tcpScanFlag(opts model.Options) string {
	if opts.UseSudo {
		return "-sS"
	}
	return "-sT"
}

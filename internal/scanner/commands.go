package scanner

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"nmaper/internal/converter"
	"nmaper/internal/model"
	"nmaper/internal/parser"
)

func BuildDiscoveryArgs(opts model.Options) []string {
	opts = effectiveOptions(opts)
	opts = discoveryPhaseOptions(opts)
	args := []string{}
	if usesHostDiscovery(opts) {
		args = append(args, "-sn")
	} else {
		if opts.UseSudo {
			args = append(args, "-sS")
		} else {
			args = append(args, "-sT")
		}
	}
	args = append(args, "-T", fmt.Sprintf("%d", opts.Timing), "-oX", "-")
	if opts.NoPing {
		args = append(args, "-Pn")
	}
	if !usesHostDiscovery(opts) {
		if opts.Ports != "" {
			args = append(args, "-p", opts.Ports)
		} else if opts.TopPorts > 0 {
			args = append(args, "--top-ports", fmt.Sprintf("%d", opts.TopPorts))
		}
	}
	if opts.SpoofMAC != "" {
		args = append(args, "--spoof-mac", opts.SpoofMAC)
	}
	args = append(args, opts.Target)
	return args
}

func BuildDetailArgs(ip string, ports []int, opts model.Options) []string {
	opts = effectiveOptions(opts)
	opts = detailPhaseOptions(ip, opts)
	return buildDetailArgs(detailProfileContext{
		IP:       ip,
		Level:    opts.Level,
		TCPPorts: ports,
		UDPPorts: detailUDPPorts(opts),
	}, opts)
}

func joinPorts(ports []int) string {
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, fmt.Sprintf("%d", port))
	}
	return strings.Join(values, ",")
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func joinProtocolPorts(tcpPorts, udpPorts []int) string {
	sections := make([]string, 0, 2)
	if len(tcpPorts) > 0 {
		sections = append(sections, "T:"+joinPorts(tcpPorts))
	}
	if len(udpPorts) > 0 {
		sections = append(sections, "U:"+joinPorts(udpPorts))
	}
	if len(sections) == 0 {
		return ""
	}
	if len(sections) == 1 {
		return sections[0]
	}
	return strings.Join(sections, ",")
}

func detailScanLabel(target converter.DetailTarget, opts model.Options) string {
	if len(target.Ports) > 0 {
		return fmt.Sprintf("detail scan for %s on ports %s", target.IP, joinProtocolPorts(target.Ports, detailUDPPorts(opts)))
	}
	return fallbackDetailScanLabel(target, opts)
}

func fallbackDetailScanLabel(target converter.DetailTarget, opts model.Options) string {
	if opts.Ports != "" {
		return fmt.Sprintf("port probe scan for %s using explicit ports %s", target.IP, opts.Ports)
	}
	if opts.TopPorts > 0 {
		return fmt.Sprintf("port probe scan for %s using top %d ports", target.IP, opts.TopPorts)
	}
	return fmt.Sprintf("port probe scan for %s", target.IP)
}

func openTCPPorts(host parser.Host) []int {
	ports := make([]int, 0)
	for _, port := range host.OpenPorts() {
		if port.Protocol != "tcp" {
			continue
		}
		ports = append(ports, port.ID)
	}
	return ports
}

func SessionName(opts model.Options) string {
	if opts.Name != "" {
		return opts.Name
	}
	return fmt.Sprintf("scan-%s", time.Now().Format("20060102-150405"))
}

func commandWithArgs(prefix, args []string) []string {
	return append(append([]string(nil), prefix...), args...)
}

func findDiscoveryHost(run parser.Run, ip string) (parser.Host, bool) {
	for _, host := range run.Hosts {
		if host.PrimaryIP() == ip {
			return host, true
		}
	}
	return parser.Host{}, false
}

func previewCommand(command []string) string {
	parts := make([]string, 0, len(command))
	for _, arg := range command {
		if strings.ContainsAny(arg, " \t\n\"'") {
			parts = append(parts, strconv.Quote(arg))
			continue
		}
		parts = append(parts, arg)
	}
	text := strings.Join(parts, " ")
	if len(text) <= 220 {
		return text
	}
	return text[:217] + "..."
}

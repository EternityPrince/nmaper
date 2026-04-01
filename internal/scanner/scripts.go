package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"nmaper/internal/model"
	"nmaper/internal/parser"
)

type detailProfileContext struct {
	IP        string
	Level     model.ScanLevel
	TCPPorts  []int
	UDPPorts  []int
	Hostnames []string
	Vendor    string
	Services  []string
	Products  []string
}

type scriptRule struct {
	MinLevel         model.ScanLevel
	TCPPorts         []int
	UDPPorts         []int
	HostnameContains []string
	VendorContains   []string
	ServiceContains  []string
	ProductContains  []string
	Scripts          []string
}

var defaultUDPPorts = []int{53, 67, 68, 123, 137, 161, 500, 1900, 5353}

var (
	availableScriptsOnce sync.Once
	availableScriptsSet  map[string]struct{}
)

var defaultScriptRules = []scriptRule{
	{
		MinLevel: model.ScanLevelLow,
		TCPPorts: []int{22, 2222},
		Scripts:  []string{"ssh-hostkey"},
	},
	{
		MinLevel: model.ScanLevelMid,
		TCPPorts: []int{22, 2222},
		Scripts:  []string{"ssh2-enum-algos"},
	},
	{
		MinLevel: model.ScanLevelHigh,
		TCPPorts: []int{22, 2222},
		Scripts:  []string{"sshv1"},
	},
	{
		MinLevel: model.ScanLevelHigh,
		TCPPorts: []int{21},
		Scripts:  []string{"ftp-vsftpd-backdoor"},
	},
	{
		MinLevel: model.ScanLevelLow,
		TCPPorts: []int{25, 465, 587},
		Scripts:  []string{"smtp-commands"},
	},
	{
		MinLevel: model.ScanLevelLow,
		TCPPorts: []int{80, 81, 3000, 8000, 8008, 8080, 8081, 8088, 8888},
		Scripts:  []string{"http-title", "http-headers", "http-server-header"},
	},
	{
		MinLevel: model.ScanLevelMid,
		TCPPorts: []int{80, 81, 3000, 8000, 8008, 8080, 8081, 8088, 8888},
		Scripts:  []string{"http-enum", "http-methods", "http-auth", "http-security-headers"},
	},
	{
		MinLevel: model.ScanLevelLow,
		TCPPorts: []int{443, 465, 636, 993, 995, 8443, 9443},
		Scripts:  []string{"ssl-cert"},
	},
	{
		MinLevel: model.ScanLevelMid,
		TCPPorts: []int{443, 465, 636, 993, 995, 8443, 9443},
		Scripts:  []string{"ssl-enum-ciphers"},
	},
	{
		MinLevel: model.ScanLevelHigh,
		TCPPorts: []int{443, 465, 636, 993, 995, 8443, 9443},
		Scripts:  []string{"ssl-heartbleed"},
	},
	{
		MinLevel: model.ScanLevelLow,
		TCPPorts: []int{443, 8443, 9443},
		Scripts:  []string{"http-title", "http-headers", "http-server-header"},
	},
	{
		MinLevel: model.ScanLevelMid,
		TCPPorts: []int{443, 8443, 9443},
		Scripts:  []string{"http-enum", "http-methods", "http-auth", "http-security-headers"},
	},
	{
		MinLevel: model.ScanLevelLow,
		TCPPorts: []int{139, 445},
		Scripts:  []string{"smb-os-discovery"},
	},
	{
		MinLevel: model.ScanLevelMid,
		TCPPorts: []int{139, 445},
		Scripts:  []string{"smb-enum-shares", "smb-protocols"},
	},
	{
		MinLevel: model.ScanLevelHigh,
		TCPPorts: []int{139, 445},
		Scripts:  []string{"smb-vuln-ms17-010"},
	},
	{
		MinLevel: model.ScanLevelLow,
		TCPPorts: []int{3389},
		Scripts:  []string{"rdp-ntlm-info"},
	},
	{
		MinLevel: model.ScanLevelMid,
		TCPPorts: []int{3389},
		Scripts:  []string{"rdp-enum-encryption"},
	},
	{
		MinLevel: model.ScanLevelHigh,
		TCPPorts: []int{3389},
		Scripts:  []string{"rdp-vuln-ms12-020"},
	},
	{
		MinLevel: model.ScanLevelHigh,
		UDPPorts: []int{53},
		Scripts:  []string{"dns-nsid", "dns-service-discovery"},
	},
	{
		MinLevel: model.ScanLevelHigh,
		UDPPorts: []int{123},
		Scripts:  []string{"ntp-info"},
	},
	{
		MinLevel: model.ScanLevelHigh,
		UDPPorts: []int{137},
		Scripts:  []string{"nbstat"},
	},
	{
		MinLevel: model.ScanLevelHigh,
		UDPPorts: []int{161},
		Scripts:  []string{"snmp-info"},
	},
	{
		MinLevel: model.ScanLevelHigh,
		UDPPorts: []int{500},
		Scripts:  []string{"ike-version"},
	},
	{
		MinLevel: model.ScanLevelHigh,
		UDPPorts: []int{1900},
		Scripts:  []string{"upnp-info"},
	},
	{
		MinLevel: model.ScanLevelHigh,
		UDPPorts: []int{5353},
		Scripts:  []string{"mdns-discovery"},
	},
}

var serviceAwareScriptRules = []scriptRule{
	{
		MinLevel:        model.ScanLevelLow,
		TCPPorts:        []int{21, 990},
		ServiceContains: []string{"ftp", "ftps"},
		Scripts:         []string{"ftp-syst"},
	},
	{
		MinLevel:        model.ScanLevelMid,
		TCPPorts:        []int{21, 990},
		ServiceContains: []string{"ftp", "ftps"},
		Scripts:         []string{"ftp-anon"},
	},
	{
		MinLevel:        model.ScanLevelHigh,
		TCPPorts:        []int{80, 81, 3000, 8000, 8008, 8080, 8081, 8088, 8888, 443, 8443, 9443},
		ServiceContains: []string{"http", "https"},
		Scripts:         []string{"http-favicon", "http-date", "http-generator", "http-robots.txt", "http-ntlm-info"},
	},
	{
		MinLevel:        model.ScanLevelHigh,
		TCPPorts:        []int{80, 81, 443, 8443, 9443},
		ServiceContains: []string{"http", "https"},
		VendorContains:  []string{"tp-link", "netgear", "d-link", "huawei", "mikrotik", "ubiquiti", "qnap", "synology", "tuya"},
		Scripts:         []string{"http-auth-finder"},
	},
	{
		MinLevel:        model.ScanLevelLow,
		TCPPorts:        []int{5000, 554, 7000, 8554},
		ServiceContains: []string{"rtsp"},
		Scripts:         []string{"rtsp-methods"},
	},
	{
		MinLevel:        model.ScanLevelLow,
		TCPPorts:        []int{5000, 7000},
		ProductContains: []string{"airtunes", "airplay", "raop"},
		Scripts:         []string{"rtsp-methods"},
	},
	{
		MinLevel:        model.ScanLevelLow,
		TCPPorts:        []int{548},
		ServiceContains: []string{"afp"},
		Scripts:         []string{"afp-serverinfo"},
	},
	{
		MinLevel:        model.ScanLevelLow,
		TCPPorts:        []int{8009},
		ServiceContains: []string{"ajp13", "ajp"},
		Scripts:         []string{"ajp-headers"},
	},
	{
		MinLevel:        model.ScanLevelMid,
		TCPPorts:        []int{8009},
		ServiceContains: []string{"ajp13", "ajp"},
		Scripts:         []string{"ajp-methods"},
	},
}

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

func effectiveDetailScripts(ctx detailProfileContext) []string {
	if len(ctx.TCPPorts) == 0 && len(ctx.UDPPorts) == 0 {
		return nil
	}
	return effectiveRecommendedScripts(ctx)
}

func effectiveRecommendedScripts(ctx detailProfileContext) []string {
	return filterAvailableScripts(mergeScripts(recommendedScripts(ctx), targetedScripts(ctx)))
}

func recommendedScripts(ctx detailProfileContext) []string {
	seen := make(map[string]struct{})
	selected := make([]string, 0)
	for _, rule := range defaultScriptRules {
		if ctx.Level.Rank() < rule.MinLevel.Rank() {
			continue
		}
		if !rule.matches(ctx) {
			continue
		}
		for _, script := range rule.Scripts {
			if _, ok := seen[script]; ok {
				continue
			}
			seen[script] = struct{}{}
			selected = append(selected, script)
		}
	}
	return selected
}

func targetedScripts(ctx detailProfileContext) []string {
	seen := make(map[string]struct{})
	selected := make([]string, 0)
	for _, rule := range serviceAwareScriptRules {
		if ctx.Level.Rank() < rule.MinLevel.Rank() {
			continue
		}
		if !rule.matches(ctx) {
			continue
		}
		for _, script := range rule.Scripts {
			if _, ok := seen[script]; ok {
				continue
			}
			seen[script] = struct{}{}
			selected = append(selected, script)
		}
	}
	return selected
}

func (r scriptRule) matches(ctx detailProfileContext) bool {
	if len(r.TCPPorts) > 0 || len(r.UDPPorts) > 0 {
		tcpMatch := len(r.TCPPorts) > 0 && matchesAnyPort(r.TCPPorts, ctx.TCPPorts)
		udpMatch := len(r.UDPPorts) > 0 && matchesAnyPort(r.UDPPorts, ctx.UDPPorts)
		if !tcpMatch && !udpMatch {
			return false
		}
	}
	if len(r.HostnameContains) > 0 && !matchesAnyHostname(r.HostnameContains, ctx.Hostnames) {
		return false
	}
	if len(r.VendorContains) > 0 && !matchesSubstring(ctx.Vendor, r.VendorContains) {
		return false
	}
	if len(r.ServiceContains) > 0 {
		if len(ctx.Services) == 0 || !matchesAnyHint(ctx.Services, r.ServiceContains) {
			return false
		}
	}
	if len(r.ProductContains) > 0 {
		if len(ctx.Products) == 0 || !matchesAnyHint(ctx.Products, r.ProductContains) {
			return false
		}
	}
	return true
}

func mergeScripts(groups ...[]string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, group := range groups {
		for _, script := range group {
			if _, ok := seen[script]; ok {
				continue
			}
			seen[script] = struct{}{}
			out = append(out, script)
		}
	}
	return out
}

func matchesAnyPort(rulePorts, targetPorts []int) bool {
	available := make(map[int]struct{}, len(targetPorts))
	for _, port := range targetPorts {
		available[port] = struct{}{}
	}
	for _, port := range rulePorts {
		if _, ok := available[port]; ok {
			return true
		}
	}
	return false
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

func matchesAnyHostname(patterns, hostnames []string) bool {
	for _, hostname := range hostnames {
		if matchesSubstring(hostname, patterns) {
			return true
		}
	}
	return false
}

func matchesSubstring(value string, patterns []string) bool {
	normalized := strings.ToLower(value)
	for _, pattern := range patterns {
		if strings.Contains(normalized, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func matchesAnyHint(values, patterns []string) bool {
	for _, value := range values {
		if matchesSubstring(value, patterns) {
			return true
		}
	}
	return false
}

func detailContextForHost(ip string, ports []int, host parser.Host, opts model.Options) detailProfileContext {
	_, vendor := host.MAC()
	return detailProfileContext{
		IP:        ip,
		Level:     opts.Level,
		TCPPorts:  ports,
		UDPPorts:  detailUDPPorts(opts),
		Hostnames: append([]string(nil), host.Hostnames...),
		Vendor:    vendor,
		Services:  openServiceNames(host),
		Products:  openServiceProducts(host),
	}
}

func openServiceNames(host parser.Host) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, port := range host.OpenPorts() {
		for _, value := range []string{port.Service.Name, port.Service.Tunnel, port.Service.ExtraInfo} {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			key := strings.ToLower(value)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, value)
		}
	}
	return out
}

func openServiceProducts(host parser.Host) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, port := range host.OpenPorts() {
		for _, value := range []string{port.Service.Product, port.Service.Version} {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			key := strings.ToLower(value)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, value)
		}
	}
	return out
}

func filterAvailableScripts(scripts []string) []string {
	available := availableScripts()
	if len(available) == 0 {
		return scripts
	}

	filtered := make([]string, 0, len(scripts))
	for _, script := range scripts {
		if _, ok := available[script]; ok {
			filtered = append(filtered, script)
		}
	}
	return filtered
}

func availableScripts() map[string]struct{} {
	availableScriptsOnce.Do(func() {
		availableScriptsSet = make(map[string]struct{})
		for _, dir := range candidateScriptDirs() {
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				name := entry.Name()
				if !strings.HasSuffix(name, ".nse") {
					continue
				}
				availableScriptsSet[strings.TrimSuffix(name, ".nse")] = struct{}{}
			}
		}
	})
	return availableScriptsSet
}

func candidateScriptDirs() []string {
	dirs := make([]string, 0, 5)
	appendDir := func(dir string) {
		if dir == "" {
			return
		}
		for _, existing := range dirs {
			if existing == dir {
				return
			}
		}
		dirs = append(dirs, dir)
	}

	appendDir(os.Getenv("NMAPER_NMAP_SCRIPTS_DIR"))
	if nmapBin := os.Getenv("NMAPER_NMAP_BIN"); filepath.IsAbs(nmapBin) {
		appendDir(filepath.Clean(filepath.Join(filepath.Dir(nmapBin), "..", "share", "nmap", "scripts")))
	}
	appendDir("/opt/homebrew/share/nmap/scripts")
	appendDir("/usr/local/share/nmap/scripts")
	appendDir("/usr/share/nmap/scripts")
	return dirs
}

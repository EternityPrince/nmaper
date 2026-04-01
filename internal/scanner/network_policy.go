package scanner

import (
	"net"
	"strings"

	"nmaper/internal/converter"
	"nmaper/internal/model"
)

func isCIDRTarget(target string) bool {
	_, _, err := net.ParseCIDR(strings.TrimSpace(target))
	return err == nil
}

func usesHostDiscovery(opts model.Options) bool {
	return isCIDRTarget(opts.Target) && !opts.NoPing
}

func shouldSuppressDiscoverySpoof(opts model.Options) bool {
	return opts.SpoofMAC != "" && (usesHostDiscovery(opts) || isTargetOnLocalNetwork(opts.Target))
}

func discoveryPhaseOptions(opts model.Options) model.Options {
	if shouldSuppressDiscoverySpoof(opts) {
		opts.SpoofMAC = ""
	}
	return opts
}

func detailPhaseOptions(target string, opts model.Options) model.Options {
	if shouldSuppressDetailSpoof(target, opts) {
		opts.SpoofMAC = ""
	}
	return opts
}

func shouldSuppressDetailSpoof(target string, opts model.Options) bool {
	return opts.SpoofMAC != "" && isTargetOnLocalNetwork(target)
}

func shouldSuppressLocalDetailSpoof(targets []converter.DetailTarget, opts model.Options) bool {
	if opts.SpoofMAC == "" {
		return false
	}
	for _, target := range targets {
		if shouldSuppressDetailSpoof(target.IP, opts) {
			return true
		}
	}
	return false
}

func isTargetOnLocalNetwork(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}

	if ip := net.ParseIP(target); ip != nil {
		return isLocalIP(ip)
	}

	_, ipNet, err := net.ParseCIDR(target)
	if err != nil {
		return false
	}
	return cidrIncludesLocalInterface(ipNet)
}

func isLocalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet == nil {
				continue
			}
			if ipNet.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func cidrIncludesLocalInterface(target *net.IPNet) bool {
	if target == nil {
		return false
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet == nil {
				continue
			}
			if target.Contains(ipNet.IP) || ipNet.Contains(target.IP) {
				return true
			}
		}
	}
	return false
}

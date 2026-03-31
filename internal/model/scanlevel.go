package model

import (
	"fmt"
	"strings"
)

func (l ScanLevel) Valid() bool {
	switch l {
	case ScanLevelLow, ScanLevelMid, ScanLevelHigh:
		return true
	default:
		return false
	}
}

func (l ScanLevel) Rank() int {
	switch l {
	case ScanLevelLow:
		return 1
	case ScanLevelMid:
		return 2
	case ScanLevelHigh:
		return 3
	default:
		return 0
	}
}

func NormalizeScanOptions(opts Options) (Options, error) {
	if opts.Level == "" {
		opts.Level = ScanLevelMid
	}
	if !opts.Level.Valid() {
		return opts, fmt.Errorf("--level must be one of: low, mid, high")
	}

	switch opts.Level {
	case ScanLevelLow:
		opts.UseSudo = false
		opts.EnableUDP = false
		opts.EnableTraceroute = false
		if opts.SpoofMAC != "" {
			return opts, fmt.Errorf("--spoof-mac is not available with --level low")
		}
		if !opts.TimingExplicit {
			opts.Timing = 3
		}
		if !opts.DetailWorkersExplicit {
			opts.DetailWorkers = 2
		}
		if !opts.ServiceVersionExplicit {
			opts.ServiceVersion = true
		}

	case ScanLevelMid:
		opts.EnableUDP = false
		opts.EnableTraceroute = true
		if !opts.TimingExplicit {
			opts.Timing = 4
		}
		if !opts.DetailWorkersExplicit {
			opts.DetailWorkers = 4
		}
		if !opts.ServiceVersionExplicit {
			opts.ServiceVersion = true
		}

	case ScanLevelHigh:
		opts.UseSudo = true
		opts.EnableUDP = true
		opts.EnableTraceroute = true
		if !opts.SpoofMACExplicit && opts.SpoofMAC == "" {
			opts.SpoofMAC = "random"
		}
		if !opts.TimingExplicit {
			opts.Timing = 4
		}
		if !opts.DetailWorkersExplicit {
			opts.DetailWorkers = 6
		}
		if !opts.ServiceVersionExplicit {
			opts.ServiceVersion = true
		}
		if !opts.OSDetectExplicit {
			opts.OSDetect = true
		}
	}

	if opts.SpoofMAC != "" && !opts.UseSudo {
		return opts, fmt.Errorf("--spoof-mac requires sudo privileges")
	}
	if !opts.EnableTraceroute && opts.OSDetect {
		opts.EnableTraceroute = true
	}
	return opts, nil
}

func ScanLevelSummary(opts Options) string {
	switch opts.Level {
	case ScanLevelLow:
		return "light unprivileged TCP scan"
	case ScanLevelMid:
		return "balanced TCP scan with richer service fingerprints"
	case ScanLevelHigh:
		return "deep privileged scan with UDP enrichment and MAC spoofing"
	default:
		return "custom scan"
	}
}

func ScanLevelCapabilities(opts Options) []string {
	capabilities := make([]string, 0, 8)
	if opts.UseSudo {
		capabilities = append(capabilities, "privileged SYN scanning")
	} else {
		capabilities = append(capabilities, "unprivileged TCP connect scanning")
	}

	switch {
	case opts.Ports != "":
		capabilities = append(capabilities, "exact ports "+opts.Ports)
	case opts.TopPorts > 0:
		capabilities = append(capabilities, fmt.Sprintf("top %d ports", opts.TopPorts))
	}

	if opts.ServiceVersion {
		capabilities = append(capabilities, "service detection")
	}
	if opts.OSDetect {
		capabilities = append(capabilities, "OS detection")
	}
	if opts.EnableTraceroute {
		capabilities = append(capabilities, "traceroute snapshots")
	}
	if opts.EnableUDP {
		capabilities = append(capabilities, "targeted UDP enrichment")
	}
	if opts.SpoofMAC != "" {
		if strings.EqualFold(opts.SpoofMAC, "random") {
			capabilities = append(capabilities, "random MAC spoofing")
		} else {
			capabilities = append(capabilities, "custom MAC spoofing")
		}
	}
	capabilities = append(capabilities, "safe NSE enrichment")
	capabilities = append(capabilities, fmt.Sprintf("%d parallel detail workers", opts.DetailWorkers))
	if opts.NoPing {
		capabilities = append(capabilities, "no-ping discovery")
	}
	return capabilities
}

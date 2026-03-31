package scanner

import (
	"crypto/rand"
	"fmt"
	"net"
	"strings"
)

type SourceIdentity struct {
	Interface  string `json:"interface,omitempty"`
	RealMAC    string `json:"real_mac,omitempty"`
	SpoofedMAC string `json:"spoofed_mac,omitempty"`
}

func (s *Scanner) ResolveSourceIdentity(target, spoofRequest string) (SourceIdentity, error) {
	if s.sourceIdentity != nil {
		return *s.sourceIdentity, nil
	}

	ifaceName, realMAC, detectErr := detectSourceMAC(target)
	if detectErr != nil && spoofRequest != "" {
		return SourceIdentity{}, fmt.Errorf("detect real source MAC: %w", detectErr)
	}

	identity := SourceIdentity{
		Interface: ifaceName,
		RealMAC:   realMAC,
	}
	if spoofRequest != "" {
		spoofedMAC, err := resolveSpoofMAC(spoofRequest)
		if err != nil {
			return SourceIdentity{}, err
		}
		identity.SpoofedMAC = spoofedMAC
	}

	s.sourceIdentity = &identity
	return identity, nil
}

func resolveSpoofMAC(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return "", nil
	case "random":
		return randomLocallyAdministeredMAC()
	default:
		parsed, err := net.ParseMAC(value)
		if err != nil {
			return "", fmt.Errorf("invalid --spoof-mac value: %w", err)
		}
		return formatMAC(parsed), nil
	}
}

func randomLocallyAdministeredMAC() (string, error) {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate spoof MAC: %w", err)
	}
	buf[0] |= 0x02
	buf[0] &^= 0x01
	return formatMAC(net.HardwareAddr(buf)), nil
}

func detectSourceMAC(target string) (string, string, error) {
	if dialTarget := representativeDialTarget(target); dialTarget != "" {
		ifaceName, mac, err := detectSourceMACByRoute(dialTarget)
		if err == nil {
			return ifaceName, mac, nil
		}
	}
	return fallbackSourceMAC()
}

func detectSourceMACByRoute(target string) (string, string, error) {
	conn, err := net.Dial("udp", net.JoinHostPort(target, "80"))
	if err != nil {
		return "", "", err
	}
	defer conn.Close()

	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "", "", fmt.Errorf("unexpected local addr type %T", conn.LocalAddr())
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return "", "", err
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.Contains(udpAddr.IP) {
				return iface.Name, formatMAC(iface.HardwareAddr), nil
			}
		}
	}
	return "", "", fmt.Errorf("no matching interface for local ip %s", udpAddr.IP)
}

func fallbackSourceMAC() (string, string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", "", err
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}
		return iface.Name, formatMAC(iface.HardwareAddr), nil
	}
	return "", "", fmt.Errorf("no active non-loopback interface with hardware address found")
}

func representativeDialTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}

	if ip := net.ParseIP(target); ip != nil {
		return ip.String()
	}
	if _, ipNet, err := net.ParseCIDR(target); err == nil {
		return firstUsableIP(ipNet).String()
	}
	return target
}

func firstUsableIP(ipNet *net.IPNet) net.IP {
	if ipNet == nil {
		return nil
	}
	ip := append(net.IP(nil), ipNet.IP...)
	if ipv4 := ip.To4(); ipv4 != nil {
		if ones, bits := ipNet.Mask.Size(); bits == 32 && ones < 32 {
			ipv4[3]++
		}
		return ipv4
	}
	return ip
}

func formatMAC(addr net.HardwareAddr) string {
	return strings.ToUpper(addr.String())
}

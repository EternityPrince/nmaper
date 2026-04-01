package snapshot

import (
	"strings"

	"nmaper/internal/parser"
)

func deriveManagement(port parser.Port, profile ServiceProfile) []ManagementSurface {
	label, category := managementDescriptor(port, profile)
	if label == "" && category == "" {
		return nil
	}

	detail := serviceDetail(port, profile)
	return []ManagementSurface{{
		Category: category,
		Label:    label,
		Port:     port.ID,
		Protocol: port.Protocol,
		Exposure: port.Service.Name,
		Detail:   detail,
	}}
}

func managementDescriptor(port parser.Port, profile ServiceProfile) (string, string) {
	switch port.ID {
	case 22, 2222:
		return "SSH", "ssh"
	case 23:
		return "Telnet", "telnet"
	case 53:
		return "DNS", "dns"
	case 137:
		return "NetBIOS", "netbios"
	case 161:
		return "SNMP", "snmp"
	case 445, 139:
		return "SMB", "smb"
	case 3389:
		return "RDP", "rdp"
	case 5900:
		return "VNC", "vnc"
	case 5985, 5986:
		return "WinRM", "winrm"
	case 8080, 8081, 8443, 9090, 9443, 10000, 15672:
		return "Admin UI", "http-admin"
	case 2375, 2376:
		return "Docker API", "docker"
	case 6443:
		return "Kubernetes API", "kubernetes"
	case 1900:
		return "UPnP", "upnp"
	}

	if isHTTPService(port) {
		title := ""
		if profile.HTTP != nil {
			title = strings.ToLower(profile.HTTP.Title)
		}
		if strings.Contains(title, "admin") || strings.Contains(title, "login") || strings.Contains(title, "console") || strings.Contains(title, "dashboard") || strings.Contains(title, "router") || strings.Contains(title, "nas") {
			return "Admin UI", "http-admin"
		}
	}
	return "", ""
}

func serviceDetail(port parser.Port, profile ServiceProfile) string {
	if profile.HTTP != nil && profile.HTTP.Title != "" {
		return profile.HTTP.Title
	}
	if profile.HTTP != nil && profile.HTTP.Server != "" {
		return profile.HTTP.Server
	}
	if profile.SMB != nil && profile.SMB.OS != "" {
		return profile.SMB.OS
	}
	if port.Service.Product != "" {
		return strings.TrimSpace(strings.Join([]string{port.Service.Product, port.Service.Version}, " "))
	}
	return port.Service.Name
}

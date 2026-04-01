package scanner

import (
	"sync"

	"nmaper/internal/model"
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

package model

type Mode string

const (
	ModeScan       Mode = "scan"
	ModeSessions   Mode = "sessions"
	ModeSession    Mode = "session"
	ModeDiff       Mode = "diff"
	ModeDiffGlobal Mode = "diff-global"
	ModeTimeline   Mode = "timeline"
	ModeDevices    Mode = "devices"
	ModeDevice     Mode = "device"
	ModeCheck      Mode = "check"
)

type SaveMode string

const (
	SaveDB  SaveMode = "db"
	SaveXML SaveMode = "xml"
)

type Options struct {
	Mode         Mode
	ShowHelp     bool
	Target       string
	SessionID    *int64
	DiffIDs      [2]int64
	DeviceQuery  string
	HostQuery    string
	DeleteTarget *int64

	Ports          string
	TopPorts       int
	OutputDir      string
	DBPath         string
	Save           SaveMode
	Name           string
	Timing         int
	NoPing         bool
	ServiceVersion bool
	OSDetect       bool
	UseSudo        bool
	DetailWorkers  int
	Verbose        bool
	Dev            bool
	Check          bool

	Limit        int
	Status       string
	TargetFilter string
	Vendor       string
	MACOnly      bool
	IPOnly       bool
	Out          string
}

func DefaultOptions() Options {
	return Options{
		Mode:          ModeScan,
		Save:          SaveDB,
		OutputDir:     "./scans",
		DBPath:        "./nmaper.db",
		Timing:        4,
		DetailWorkers: 4,
		Limit:         10,
		Out:           "clipboard",
	}
}

func (o Options) NeedsDatabase() bool {
	switch o.Mode {
	case ModeScan:
		return o.Save == SaveDB
	case ModeCheck:
		return false
	default:
		return true
	}
}

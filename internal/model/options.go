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

type ScanLevel string

const (
	ScanLevelLow  ScanLevel = "low"
	ScanLevelMid  ScanLevel = "mid"
	ScanLevelHigh ScanLevel = "high"
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
	Level        ScanLevel

	Ports            string
	TopPorts         int
	OutputDir        string
	DBPath           string
	Save             SaveMode
	Name             string
	Timing           int
	NoPing           bool
	ServiceVersion   bool
	OSDetect         bool
	UseSudo          bool
	SpoofMAC         string
	DetailWorkers    int
	Verbose          bool
	Dev              bool
	Check            bool
	EnableUDP        bool
	EnableTraceroute bool

	LevelExplicit          bool
	TopPortsExplicit       bool
	TimingExplicit         bool
	ServiceVersionExplicit bool
	OSDetectExplicit       bool
	UseSudoExplicit        bool
	SpoofMACExplicit       bool
	DetailWorkersExplicit  bool

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
		Level:         ScanLevelMid,
		Save:          SaveDB,
		OutputDir:     "./scans",
		DBPath:        "./nmaper.db",
		TopPorts:      1000,
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

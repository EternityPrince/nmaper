package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"nmaper/internal/model"
)

var errHelp = errors.New("help requested")

func Parse(args []string) (model.Options, error) {
	opts := model.DefaultOptions()

	var primaryModes []model.Mode
	for i := 0; i < len(args); i++ {
		token := args[i]
		switch {
		case token == "-h" || token == "--help":
			opts.ShowHelp = true
			return opts, errHelp
		case token == "--sessions":
			primaryModes = append(primaryModes, model.ModeSessions)
			opts.Mode = model.ModeSessions
		case token == "--session":
			primaryModes = append(primaryModes, model.ModeSession)
			opts.Mode = model.ModeSession
			if value, ok := optionalInt(args, i+1); ok {
				opts.SessionID = &value
				i++
			}
		case strings.HasPrefix(token, "--session="):
			value, err := parseInt(strings.TrimPrefix(token, "--session="), "--session")
			if err != nil {
				return opts, err
			}
			primaryModes = append(primaryModes, model.ModeSession)
			opts.Mode = model.ModeSession
			opts.SessionID = &value
		case token == "--diff":
			primaryModes = append(primaryModes, model.ModeDiff)
			opts.Mode = model.ModeDiff
			if i+2 >= len(args) {
				return opts, fmt.Errorf("--diff requires two session ids")
			}
			left, err := parseInt(args[i+1], "--diff")
			if err != nil {
				return opts, err
			}
			right, err := parseInt(args[i+2], "--diff")
			if err != nil {
				return opts, err
			}
			opts.DiffIDs = [2]int64{left, right}
			i += 2
		case token == "--diff-global":
			primaryModes = append(primaryModes, model.ModeDiffGlobal)
			opts.Mode = model.ModeDiffGlobal
		case token == "--timeline":
			primaryModes = append(primaryModes, model.ModeTimeline)
			opts.Mode = model.ModeTimeline
		case token == "--devices":
			primaryModes = append(primaryModes, model.ModeDevices)
			opts.Mode = model.ModeDevices
		case token == "--device" || strings.HasPrefix(token, "--device="):
			primaryModes = append(primaryModes, model.ModeDevice)
			opts.Mode = model.ModeDevice
			value, next, err := requiredValue(token, "--device", args, i)
			if err != nil {
				return opts, err
			}
			opts.DeviceQuery = value
			i = next
		case token == "--del" || strings.HasPrefix(token, "--del="):
			value, next, err := requiredValue(token, "--del", args, i)
			if err != nil {
				return opts, err
			}
			parsed, err := parseInt(value, "--del")
			if err != nil {
				return opts, err
			}
			opts.DeleteTarget = &parsed
			i = next
		case token == "--host" || strings.HasPrefix(token, "--host="):
			value, next, err := requiredValue(token, "--host", args, i)
			if err != nil {
				return opts, err
			}
			opts.HostQuery = value
			i = next
		case token == "-p" || token == "--ports" || token == "--ports=" || strings.HasPrefix(token, "-p") || strings.HasPrefix(token, "--ports="):
			value, next, err := requiredValue(token, "--ports", args, i)
			if err != nil {
				return opts, err
			}
			opts.Ports = value
			i = next
		case token == "--top-ports" || strings.HasPrefix(token, "--top-ports="):
			value, next, err := requiredValue(token, "--top-ports", args, i)
			if err != nil {
				return opts, err
			}
			parsed, err := parsePositiveInt(value, "--top-ports")
			if err != nil {
				return opts, err
			}
			opts.TopPorts = parsed
			i = next
		case token == "-o" || token == "--output" || strings.HasPrefix(token, "--output=") || strings.HasPrefix(token, "-o"):
			value, next, err := requiredValue(token, "--output", args, i)
			if err != nil {
				return opts, err
			}
			opts.OutputDir = value
			i = next
		case token == "--db" || strings.HasPrefix(token, "--db="):
			value, next, err := requiredValue(token, "--db", args, i)
			if err != nil {
				return opts, err
			}
			opts.DBPath = value
			i = next
		case token == "--save" || strings.HasPrefix(token, "--save="):
			value, next, err := requiredValue(token, "--save", args, i)
			if err != nil {
				return opts, err
			}
			opts.Save = model.SaveMode(value)
			i = next
		case token == "-n" || token == "--name" || strings.HasPrefix(token, "--name=") || strings.HasPrefix(token, "-n"):
			value, next, err := requiredValue(token, "--name", args, i)
			if err != nil {
				return opts, err
			}
			opts.Name = value
			i = next
		case token == "-T" || strings.HasPrefix(token, "-T") || token == "--timing" || strings.HasPrefix(token, "--timing="):
			value, next, err := requiredValue(token, "-T", args, i)
			if err != nil {
				return opts, err
			}
			parsed, err := parseInt(value, "-T")
			if err != nil {
				return opts, err
			}
			opts.Timing = int(parsed)
			i = next
		case token == "--no-ping":
			opts.NoPing = true
		case token == "--service-version":
			opts.ServiceVersion = true
		case token == "--os-detect":
			opts.OSDetect = true
		case token == "--sudo":
			opts.UseSudo = true
		case token == "--detail-workers" || strings.HasPrefix(token, "--detail-workers="):
			value, next, err := requiredValue(token, "--detail-workers", args, i)
			if err != nil {
				return opts, err
			}
			parsed, err := parsePositiveInt(value, "--detail-workers")
			if err != nil {
				return opts, err
			}
			opts.DetailWorkers = parsed
			i = next
		case token == "--verbose":
			opts.Verbose = true
		case token == "--limit" || strings.HasPrefix(token, "--limit="):
			value, next, err := requiredValue(token, "--limit", args, i)
			if err != nil {
				return opts, err
			}
			parsed, err := parsePositiveInt(value, "--limit")
			if err != nil {
				return opts, err
			}
			opts.Limit = parsed
			i = next
		case token == "--status" || strings.HasPrefix(token, "--status="):
			value, next, err := requiredValue(token, "--status", args, i)
			if err != nil {
				return opts, err
			}
			opts.Status = value
			i = next
		case token == "--target-filter" || strings.HasPrefix(token, "--target-filter="):
			value, next, err := requiredValue(token, "--target-filter", args, i)
			if err != nil {
				return opts, err
			}
			opts.TargetFilter = value
			i = next
		case token == "--vendor" || strings.HasPrefix(token, "--vendor="):
			value, next, err := requiredValue(token, "--vendor", args, i)
			if err != nil {
				return opts, err
			}
			opts.Vendor = value
			i = next
		case token == "--mac-only":
			opts.MACOnly = true
		case token == "--ip-only":
			opts.IPOnly = true
		case token == "--out" || strings.HasPrefix(token, "--out="):
			value, next, err := requiredValue(token, "--out", args, i)
			if err != nil {
				return opts, err
			}
			opts.Out = value
			i = next
		case token == "--check":
			opts.Check = true
			opts.Mode = model.ModeCheck
		case token == "--dev":
			opts.Dev = true
		case strings.HasPrefix(token, "-"):
			return opts, fmt.Errorf("unknown flag: %s", token)
		default:
			if opts.Target != "" {
				return opts, fmt.Errorf("unexpected positional argument: %s", token)
			}
			opts.Target = token
		}
	}

	if opts.Check {
		opts.Mode = model.ModeCheck
	}

	if err := validate(opts, primaryModes); err != nil {
		return opts, err
	}

	if len(primaryModes) == 0 && !opts.Check {
		opts.Mode = model.ModeScan
	}
	if opts.Mode == model.ModeSession && opts.SessionID == nil && opts.DeleteTarget == nil {
		opts.Mode = model.ModeSessions
	}

	return opts, nil
}

func IsHelp(err error) bool {
	return errors.Is(err, errHelp)
}

func validate(opts model.Options, primaryModes []model.Mode) error {
	if len(primaryModes) > 1 {
		return fmt.Errorf("only one primary history mode can be selected at a time")
	}
	if opts.DeleteTarget != nil {
		if opts.Mode != model.ModeSession {
			return fmt.Errorf("--del can only be used with --session")
		}
		if opts.SessionID != nil {
			return fmt.Errorf("--del cannot be combined with --session <id>")
		}
	}
	if opts.HostQuery != "" {
		if opts.Mode != model.ModeSession || opts.SessionID == nil {
			return fmt.Errorf("--host can only be used with --session <id>")
		}
	}
	if opts.Vendor != "" && opts.Mode != model.ModeDevices && opts.Mode != model.ModeDevice {
		return fmt.Errorf("--vendor can only be used with --devices or --device")
	}
	if opts.MACOnly && opts.IPOnly {
		return fmt.Errorf("--mac-only and --ip-only cannot be used together")
	}
	if opts.DetailWorkers < 1 {
		return fmt.Errorf("--detail-workers must be at least 1")
	}
	if opts.Limit < 1 {
		return fmt.Errorf("--limit must be at least 1")
	}
	if opts.Timing < 0 || opts.Timing > 5 {
		return fmt.Errorf("-T must be between 0 and 5")
	}
	if opts.Ports != "" && opts.TopPorts > 0 {
		return fmt.Errorf("--ports and --top-ports are mutually exclusive")
	}
	if opts.Save != model.SaveDB && opts.Save != model.SaveXML {
		return fmt.Errorf("--save must be one of: db, xml")
	}

	if opts.Mode != model.ModeScan && opts.Mode != model.ModeCheck && opts.Target != "" {
		return fmt.Errorf("target is not allowed in history modes")
	}
	if opts.Mode == model.ModeScan && opts.Target == "" {
		return fmt.Errorf("target is required in scan mode")
	}
	return nil
}

func requiredValue(token, longName string, args []string, index int) (string, int, error) {
	if strings.Contains(token, "=") {
		parts := strings.SplitN(token, "=", 2)
		if parts[1] == "" {
			return "", index, fmt.Errorf("%s requires a value", longName)
		}
		return parts[1], index, nil
	}

	switch {
	case strings.HasPrefix(token, "-p") && token != "-p":
		return strings.TrimPrefix(token, "-p"), index, nil
	case strings.HasPrefix(token, "-o") && token != "-o":
		return strings.TrimPrefix(token, "-o"), index, nil
	case strings.HasPrefix(token, "-n") && token != "-n":
		return strings.TrimPrefix(token, "-n"), index, nil
	case strings.HasPrefix(token, "-T") && token != "-T":
		return strings.TrimPrefix(token, "-T"), index, nil
	}

	if index+1 >= len(args) {
		return "", index, fmt.Errorf("%s requires a value", longName)
	}
	return args[index+1], index + 1, nil
}

func parseInt(value, flagName string) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s expects an integer value", flagName)
	}
	return parsed, nil
}

func parsePositiveInt(value, flagName string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s expects an integer value", flagName)
	}
	if parsed < 1 {
		return 0, fmt.Errorf("%s must be at least 1", flagName)
	}
	return parsed, nil
}

func optionalInt(args []string, index int) (int64, bool) {
	if index >= len(args) {
		return 0, false
	}
	parsed, err := strconv.ParseInt(args[index], 10, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func Usage() string {
	return strings.TrimSpace(`
Usage:
  nmaper [target] [scan options]
  nmaper --sessions [filters]
  nmaper --session [id] [--host query] [--out clipboard|md|json|file:path]
  nmaper --diff <id1> <id2> [--out md|json|file:path]
  nmaper --diff-global [--limit N]
  nmaper --devices [--vendor query] [--mac-only|--ip-only]
  nmaper --device <query> [--vendor query]
  nmaper --timeline [--limit N]
  nmaper --session --del <id|-1>
  nmaper --check

Scan options:
  -p, --ports <ports>          Exact nmap port list
      --top-ports <N>          Scan top N ports
  -o, --output <dir>           Output directory for XML artifacts
      --db <path>              SQLite database path
      --save <db|xml>          Storage mode
  -n, --name <name>            Human-readable session name
  -T <0..5>                    Nmap timing template
      --no-ping                Disable host discovery ping
      --service-version        Add -sV to detail scan
      --os-detect              Add -O to detail scan
      --sudo                   Warm sudo and run nmap via sudo -n
      --detail-workers <N>     Parallel detail scans
      --verbose                Verbose runtime logging
      --dev                    Run preflight before scan

History options:
      --limit <N>              Limit number of records
      --status <value>         Session status filter
      --target-filter <query>  Fuzzy target filter
      --vendor <query>         Device vendor filter
      --mac-only               Only MAC-backed devices
      --ip-only                Only IP-only devices
      --out <mode>             clipboard, md, json, terminal, file:<path>
`)
}

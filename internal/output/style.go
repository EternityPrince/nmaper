package output

import (
	"fmt"
	"regexp"
	"strings"
)

const timeLayout = "2006-01-02 15:04:05"

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
)

func terminalTitle(title string) string {
	line := strings.Repeat("=", maxInt(len(title), 12))
	return style(title, ansiBold, ansiCyan) + "\n" + style(line, ansiDim) + "\n"
}

func terminalSection(title string) string {
	line := strings.Repeat("-", maxInt(len(title), 8))
	return "\n" + style(title, ansiBold, ansiBlue) + "\n" + style(line, ansiDim) + "\n"
}

func summaryLine(label, value string) string {
	return fmt.Sprintf("%s %s\n", style(label+":", ansiDim), value)
}

func statusBadge(status string) string {
	normalized := strings.ToLower(strings.TrimSpace(status))
	switch normalized {
	case "completed", "up", "open":
		return style("["+strings.ToUpper(emptyDash(status))+"]", ansiBold, ansiGreen)
	case "running":
		return style("["+strings.ToUpper(emptyDash(status))+"]", ansiBold, ansiCyan)
	case "failed", "down", "closed":
		return style("["+strings.ToUpper(emptyDash(status))+"]", ansiBold, ansiRed)
	default:
		return style("["+strings.ToUpper(emptyDash(status))+"]", ansiBold, ansiYellow)
	}
}

func accent(value string) string {
	return style(value, ansiBold, ansiCyan)
}

func highlight(value string) string {
	return style(value, ansiBold)
}

func goodText(value string) string {
	return style(value, ansiBold, ansiGreen)
}

func warnText(value string) string {
	return style(value, ansiBold, ansiYellow)
}

func badText(value string) string {
	return style(value, ansiBold, ansiRed)
}

func style(text string, codes ...string) string {
	if text == "" {
		return ""
	}
	var builder strings.Builder
	for _, code := range codes {
		builder.WriteString(code)
	}
	builder.WriteString(text)
	builder.WriteString(ansiReset)
	return builder.String()
}

func stripANSI(text string) string {
	return ansiPattern.ReplaceAllString(text, "")
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

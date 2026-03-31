package termui

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Logger struct {
	mu      sync.Mutex
	out     io.Writer
	verbose bool
	color   bool
}

func New(out io.Writer, verbose bool) *Logger {
	return &Logger{
		out:     out,
		verbose: verbose,
		color:   isTTY(out),
	}
}

func (l *Logger) Phasef(format string, args ...any) {
	l.log("PHASE", "\033[36m", fmt.Sprintf(format, args...), true)
}

func (l *Logger) Infof(format string, args ...any) {
	l.log("INFO", "\033[34m", fmt.Sprintf(format, args...), l.verbose)
}

func (l *Logger) OKf(format string, args ...any) {
	l.log("OK", "\033[32m", fmt.Sprintf(format, args...), true)
}

func (l *Logger) Warnf(format string, args ...any) {
	l.log("WARN", "\033[33m", fmt.Sprintf(format, args...), true)
}

func (l *Logger) Failf(format string, args ...any) {
	l.log("FAIL", "\033[31m", fmt.Sprintf(format, args...), true)
}

func (l *Logger) log(level, color, message string, enabled bool) {
	if !enabled {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	prefix := level
	if l.color {
		prefix = color + level + "\033[0m"
	}
	fmt.Fprintf(l.out, "[%s] %s %s\n", prefix, time.Now().Format("15:04:05"), message)
}

func isTTY(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

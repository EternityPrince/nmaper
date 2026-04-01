package output

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type logger interface {
	Warnf(string, ...any)
}

type renderMode string

const (
	modeTerminal renderMode = "terminal"
	modeMarkdown renderMode = "markdown"
	modeJSON     renderMode = "json"
)

type sinkType string

const (
	sinkStdout    sinkType = "stdout"
	sinkClipboard sinkType = "clipboard"
	sinkFile      sinkType = "file"
)

func Resolve(out string) (renderMode, sinkType, string) {
	switch {
	case out == "", out == "clipboard":
		return modeTerminal, sinkClipboard, ""
	case out == "md":
		return modeMarkdown, sinkStdout, ""
	case out == "json":
		return modeJSON, sinkStdout, ""
	case out == "terminal":
		return modeTerminal, sinkStdout, ""
	case strings.HasPrefix(out, "file:"):
		path := strings.TrimPrefix(out, "file:")
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".md", ".markdown":
			return modeMarkdown, sinkFile, path
		case ".json":
			return modeJSON, sinkFile, path
		default:
			return modeTerminal, sinkFile, path
		}
	default:
		return modeTerminal, sinkStdout, ""
	}
}

func Emit(text string, out string, stdout io.Writer, log logger) error {
	mode, sink, path := Resolve(out)
	visibleText := text
	persistedText := text
	if mode == modeTerminal {
		persistedText = stripANSI(text)
		if !isTTYWriter(stdout) {
			visibleText = persistedText
		}
	}
	switch sink {
	case sinkFile:
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
			return err
		}
		return os.WriteFile(path, []byte(persistedText), 0o644)
	case sinkClipboard:
		if _, err := io.WriteString(stdout, visibleText); err != nil {
			return err
		}
		if !strings.HasSuffix(visibleText, "\n") {
			if _, err := io.WriteString(stdout, "\n"); err != nil {
				return err
			}
		}
		if err := copyToClipboard(persistedText); err != nil && log != nil {
			log.Warnf("clipboard copy failed: %v", err)
		}
		return nil
	default:
		if _, err := io.WriteString(stdout, visibleText); err != nil {
			return err
		}
		if !strings.HasSuffix(visibleText, "\n") {
			_, err := io.WriteString(stdout, "\n")
			return err
		}
		return nil
	}
}

func copyToClipboard(text string) error {
	if _, err := exec.LookPath("pbcopy"); err != nil {
		return err
	}
	cmd := exec.Command("pbcopy")
	cmd.Stdin = bytes.NewBufferString(text)
	return cmd.Run()
}

func isTTYWriter(writer io.Writer) bool {
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

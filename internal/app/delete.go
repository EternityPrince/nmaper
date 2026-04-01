package app

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"nmaper/internal/model"
	"nmaper/internal/termui"
)

func runDelete(ctx context.Context, opts model.Options, stdin io.Reader, stdout io.Writer, logger *termui.Logger) int {
	store, err := openStore(opts.DBPath)
	if err != nil {
		logger.Failf("open database: %v", err)
		return 1
	}
	defer store.Close()

	confirmed, err := confirmDeletion(stdin, stdout, *opts.DeleteTarget)
	if err != nil {
		logger.Failf("%v", err)
		return 1
	}
	if !confirmed {
		fmt.Fprintln(stdout, "Deletion cancelled.")
		return 0
	}

	if *opts.DeleteTarget == -1 {
		if err := store.DeleteAll(ctx); err != nil {
			logger.Failf("delete all sessions: %v", err)
			return 1
		}
		fmt.Fprintln(stdout, "All sessions deleted.")
		return 0
	}

	if err := store.DeleteSession(ctx, *opts.DeleteTarget); err != nil {
		logger.Failf("delete session: %v", err)
		return 1
	}
	fmt.Fprintf(stdout, "Session %d deleted.\n", *opts.DeleteTarget)
	return 0
}

func confirmDeletion(stdin io.Reader, stdout io.Writer, deleteTarget int64) (bool, error) {
	if !isTTY(stdin) || !isTTYWriter(stdout) {
		return false, fmt.Errorf("delete requires an interactive TTY")
	}
	prompt := fmt.Sprintf("Delete session %d? [y/N]: ", deleteTarget)
	if deleteTarget == -1 {
		prompt = "Delete all sessions? [y/N]: "
	}
	if _, err := fmt.Fprint(stdout, prompt); err != nil {
		return false, err
	}
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(line), "y"), nil
}

func isTTY(reader io.Reader) bool {
	file, ok := reader.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
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

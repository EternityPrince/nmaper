package scanner

import (
	"os"
	"path/filepath"
	"strings"
)

func filterAvailableScripts(scripts []string) []string {
	available := availableScripts()
	if len(available) == 0 {
		return scripts
	}

	filtered := make([]string, 0, len(scripts))
	for _, script := range scripts {
		if _, ok := available[script]; ok {
			filtered = append(filtered, script)
		}
	}
	return filtered
}

func availableScripts() map[string]struct{} {
	availableScriptsOnce.Do(func() {
		availableScriptsSet = make(map[string]struct{})
		for _, dir := range candidateScriptDirs() {
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				name := entry.Name()
				if !strings.HasSuffix(name, ".nse") {
					continue
				}
				availableScriptsSet[strings.TrimSuffix(name, ".nse")] = struct{}{}
			}
		}
	})
	return availableScriptsSet
}

func candidateScriptDirs() []string {
	dirs := make([]string, 0, 5)
	appendDir := func(dir string) {
		if dir == "" {
			return
		}
		for _, existing := range dirs {
			if existing == dir {
				return
			}
		}
		dirs = append(dirs, dir)
	}

	appendDir(os.Getenv("NMAPER_NMAP_SCRIPTS_DIR"))
	if nmapBin := os.Getenv("NMAPER_NMAP_BIN"); filepath.IsAbs(nmapBin) {
		appendDir(filepath.Clean(filepath.Join(filepath.Dir(nmapBin), "..", "share", "nmap", "scripts")))
	}
	appendDir("/opt/homebrew/share/nmap/scripts")
	appendDir("/usr/local/share/nmap/scripts")
	appendDir("/usr/share/nmap/scripts")
	return dirs
}

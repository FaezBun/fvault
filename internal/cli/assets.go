package cli

import (
	"os"
	"path/filepath"
)

// resolveAssetDir finds the templates or static directory. The order is:
// explicit flag, environment variable, current directory, next to the binary,
// ../share/fvault relative to the binary, then the user data directory.
func resolveAssetDir(flagValue, envKey, name string) string {
	if flagValue != "" {
		return flagValue
	}
	if value := os.Getenv(envKey); value != "" {
		return value
	}
	if isDir(name) {
		return name
	}

	var candidates []string
	if executable, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(executable); err == nil {
			executable = resolved
		}
		dir := filepath.Dir(executable)
		candidates = append(candidates,
			filepath.Join(dir, name),
			filepath.Join(dir, "..", "share", "fvault", name),
		)
	}
	if data := dataHome(); data != "" {
		candidates = append(candidates, filepath.Join(data, "fvault", name))
	}
	for _, candidate := range candidates {
		if isDir(candidate) {
			return candidate
		}
	}
	return name
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func dataHome() string {
	if value := os.Getenv("XDG_DATA_HOME"); value != "" {
		return value
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "share")
}

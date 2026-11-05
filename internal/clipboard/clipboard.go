package clipboard

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/atotto/clipboard"
)

// Copy writes text to the system clipboard. If clearAfter > 0, a detached
// helper process clears the clipboard later, but only if the content is still
// the value that was copied.
func Copy(text string, clearAfter time.Duration) (bool, error) {
	if err := clipboard.WriteAll(text); err != nil {
		return false, err
	}
	if clearAfter <= 0 {
		return false, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return false, nil
	}
	cmd := exec.Command(exe, "__clipboard-clear", Hash(text), fmt.Sprintf("%d", int(clearAfter.Seconds())))
	cmd.Env = os.Environ()
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return false, nil
	}
	_ = cmd.Process.Release()
	return true, nil
}

func Hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ClearIfMatches is used by the hidden helper command.
func ClearIfMatches(hash string, delay time.Duration) error {
	if delay > 0 {
		time.Sleep(delay)
	}
	current, err := clipboard.ReadAll()
	if err != nil {
		return err
	}
	if Hash(current) != hash {
		return nil
	}
	return clipboard.WriteAll("")
}

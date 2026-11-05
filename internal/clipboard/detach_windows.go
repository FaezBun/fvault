//go:build windows

package clipboard

import (
	"os/exec"
	"syscall"
)

const detachedProcess = 0x00000008

func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedProcess}
}

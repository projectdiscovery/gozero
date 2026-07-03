//go:build unix

package confine

import (
	"os/exec"
	"syscall"
)

// configureProcessGroup puts the confined command in its own process group and
// makes context cancellation kill the entire group. Without this, killing the
// launcher (e.g. sandbox-exec) on timeout leaves the reparented interpreter and
// its children alive; because they inherit the stdout/stderr pipes, cmd.Wait
// would block until they exit, defeating Policy.Timeout.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative pid targets the whole process group.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

//go:build !unix

package confine

import "os/exec"

// configureProcessGroup is a no-op on platforms without POSIX process groups;
// the WaitDelay backstop in runHost still bounds a stuck wait.
func configureProcessGroup(cmd *exec.Cmd) {}

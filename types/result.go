package types

import (
	"bytes"
	"os/exec"
)

// Note:
// Current use-case does not return a >1mb output from the command
// so we use bytes.Buffer instead of os.File (temporary file)
// with use case changes we can change this to os.File later

// Result contains the result of a command execution.
type Result struct {
	Command   string // Include final command that was executed
	Stdout    bytes.Buffer
	Stderr    bytes.Buffer
	exitErr   *exec.ExitError // return exit error this includes exit code , command sysusage and more
	exitCode  *int            // explicit exit code for backends without an *exec.ExitError (e.g. containers)
	DebugData *bytes.Buffer   // only available when debug mode is enabled
}

// GetExitError returns the exit error if any.
func (r *Result) GetExitError() *exec.ExitError {
	return r.exitErr
}

// SetExitError sets the exit error (internal use only).
func (r *Result) SetExitError(err *exec.ExitError) {
	r.exitErr = err
}

// SetExitCode records an explicit exit code for execution backends that do not
// surface an *exec.ExitError (e.g. containers, where the code comes from the
// daemon's wait response). It takes precedence over the exit error.
func (r *Result) SetExitCode(code int) {
	r.exitCode = &code
}

// GetExitCode returns the exit code of the command.
func (r *Result) GetExitCode() int {
	if r.exitCode != nil {
		return *r.exitCode
	}
	if r.exitErr == nil {
		return 0
	}
	return r.exitErr.ExitCode()
}

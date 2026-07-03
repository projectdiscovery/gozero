package confine

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"

	"github.com/projectdiscovery/gozero/types"
	"github.com/projectdiscovery/utils/errkit"
)

// runHost executes a fully-formed argv with an explicit, scrubbed environment
// and captures the result. It is the shared execution primitive for the native
// confiners (bubblewrap/Seatbelt), which run the payload as a child of this
// process wrapped by a sandbox launcher.
//
// Unlike gozero/cmdexec, this NEVER inherits the ambient host environment:
// cmd.Env is set to exactly env (a non-nil, possibly empty slice), so secrets
// in os.Environ() cannot leak to the payload through a native confiner that
// (like sandbox-exec) forwards its own environment to the child.
func runHost(ctx context.Context, argv, env []string, stdin io.Reader, dir string, debug bool) (*types.Result, error) {
	if len(argv) == 0 {
		return nil, ErrNoCommand
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	// Force an explicit environment. A nil slice would inherit the parent's, so
	// we always assign — even when empty — to guarantee a clean environment.
	if env == nil {
		env = []string{}
	}
	cmd.Env = env
	if dir != "" {
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			cmd.Dir = dir
		}
	}
	if stdin != nil {
		cmd.Stdin = stdin
	}

	res := &types.Result{Command: cmd.String()}
	if debug {
		res.DebugData = &bytes.Buffer{}
		cmd.Stdout = io.MultiWriter(&res.Stdout, res.DebugData)
		cmd.Stderr = io.MultiWriter(&res.Stderr, res.DebugData)
	} else {
		cmd.Stdout = &res.Stdout
		cmd.Stderr = &res.Stderr
	}

	if err := cmd.Start(); err != nil {
		return res, errkit.WithMessagef(err, "failed to start confined command got: %v", res.Stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		if execErr, ok := err.(*exec.ExitError); ok {
			res.SetExitError(execErr)
			res.SetExitCode(execErr.ExitCode())
		}
		return res, errkit.WithMessagef(err, "confined command failed got: %v", res.Stderr.String())
	}
	return res, nil
}

// remapScript returns a copy of argv with the script path (if present) replaced
// by dst and, when replaceInterp is set, the interpreter (argv[0]) replaced by
// interp. Used by backends that relocate the source into the sandbox (Docker
// copies it to a container path; the interpreter is referenced by base name
// because the host's absolute path is meaningless in the image).
func remapScript(argv []string, scriptPath, dst, interp string, replaceInterp bool) []string {
	out := make([]string, len(argv))
	copy(out, argv)
	for i, v := range out {
		if scriptPath != "" && v == scriptPath {
			out[i] = dst
		}
	}
	if replaceInterp && len(out) > 0 {
		out[0] = interp
	}
	return out
}

// ensureWorkspace returns the workspace to use for an execution and whether the
// caller owns (must clean up) it. When spec.Workdir is set it is used as-is
// (not owned); otherwise an ephemeral directory is created under the policy's
// temp dir (owned).
func ensureWorkspace(p Policy, spec Spec) (dir string, owned bool, err error) {
	if spec.Workdir != "" {
		return spec.Workdir, false, nil
	}
	if p.Workspace != "" {
		return p.Workspace, false, nil
	}
	base := p.Tmp
	if base == "" {
		base = os.TempDir()
	}
	dir, err = os.MkdirTemp(base, "gozero-confine-*")
	if err != nil {
		return "", false, err
	}
	return dir, true, nil
}

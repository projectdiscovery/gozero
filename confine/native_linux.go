//go:build linux

package confine

import (
	"context"
	"os"
	"os/exec"

	"github.com/projectdiscovery/gozero/types"
)

// newNativeConfiner returns a bubblewrap confiner when bwrap is on PATH, else
// nil so New fails closed.
func newNativeConfiner(p Policy) Confiner {
	bin, err := exec.LookPath("bwrap")
	if err != nil {
		p.Logger.Debug("confine: bubblewrap unavailable", "reason", "bwrap not found on PATH")
		return nil
	}
	return &bubblewrapConfiner{bin: bin, policy: p}
}

var _ Confiner = (*bubblewrapConfiner)(nil)

// bubblewrapConfiner confines the payload on Linux via bubblewrap.
type bubblewrapConfiner struct {
	bin    string
	policy Policy
}

func (c *bubblewrapConfiner) Name() string { return "bubblewrap" }
func (c *bubblewrapConfiner) Close() error { return nil }

func (c *bubblewrapConfiner) Run(ctx context.Context, spec Spec) (*types.Result, error) {
	if len(spec.Command) == 0 {
		return nil, ErrNoCommand
	}

	ctx, cancel := withTimeout(ctx, c.policy.Timeout)
	defer cancel()

	ws, owned, err := ensureWorkspace(c.policy, spec)
	if err != nil {
		return nil, err
	}
	if owned {
		defer func() { _ = os.RemoveAll(ws) }()
	}

	env := childEnv(c.policy, ws, spec.Env)
	argv := bwrapArgs(c.bin, c.policy, ws, spec.ScriptPath, env, spec.Command)

	// The bwrap launcher itself needs no environment: the child's environment is
	// injected via --setenv, so we run the wrapper with an empty environment as
	// defense in depth.
	return runHost(ctx, argv, []string{}, spec.Stdin, "", spec.Debug)
}

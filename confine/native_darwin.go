//go:build darwin

package confine

import (
	"context"
	"os"
	"os/exec"

	"github.com/projectdiscovery/gozero/types"
)

// newNativeConfiner returns a Seatbelt confiner when sandbox-exec is on PATH,
// else nil so New fails closed.
func newNativeConfiner(p Policy) Confiner {
	bin, err := exec.LookPath("sandbox-exec")
	if err != nil {
		p.Logger.Debug("confine: seatbelt unavailable", "reason", "sandbox-exec not found on PATH")
		return nil
	}
	return &seatbeltConfiner{bin: bin, policy: p}
}

var _ Confiner = (*seatbeltConfiner)(nil)

// seatbeltConfiner confines the payload on macOS via sandbox-exec + an SBPL
// profile. sandbox-exec forwards its own environment to the child, so we run it
// with the scrubbed environment directly (no --setenv equivalent exists).
type seatbeltConfiner struct {
	bin    string
	policy Policy
}

func (c *seatbeltConfiner) Name() string { return "seatbelt" }
func (c *seatbeltConfiner) Close() error { return nil }

func (c *seatbeltConfiner) Run(ctx context.Context, spec Spec) (*types.Result, error) {
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

	profile := seatbeltProfile(ws, c.policy.Tmp, c.policy.AllowNetwork)

	argv := make([]string, 0, len(spec.Command)+3)
	argv = append(argv, c.bin, "-p", profile)
	argv = append(argv, spec.Command...)

	env := childEnv(c.policy, ws, spec.Env)
	return runHost(ctx, argv, envMapToSlice(env), spec.Stdin, ws, spec.Debug)
}

//go:build darwin

package confine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"

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
	if err := probeSeatbelt(bin); err != nil {
		p.Logger.Debug("confine: seatbelt unavailable", "reason", "probe failed", "error", err)
		return nil
	}
	return &seatbeltConfiner{bin: bin, policy: p}
}

// seatbeltProbes caches one probe result per sandbox-exec binary.
var seatbeltProbes sync.Map

// probeSeatbelt checks that sandbox-exec can apply a profile here: it fails,
// for example, when the process already runs inside another sandbox.
func probeSeatbelt(bin string) error {
	if v, ok := seatbeltProbes.Load(bin); ok {
		if v == nil {
			return nil
		}
		return v.(error)
	}
	out, err := exec.Command(bin, "-p", "(version 1)(allow default)", "/usr/bin/true").CombinedOutput()
	if err != nil {
		err = fmt.Errorf("%w: %s", err, out)
		seatbeltProbes.Store(bin, err)
		return err
	}
	seatbeltProbes.Store(bin, nil)
	return nil
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

	profile := seatbeltProfile(c.policy, ws, spec.ScriptPath)

	argv := make([]string, 0, len(spec.Command)+3)
	argv = append(argv, c.bin, "-p", profile)
	argv = append(argv, spec.Command...)

	env := childEnv(c.policy, ws, spec.Env)
	return runHost(ctx, argv, envMapToSlice(env), spec.Stdin, ws, spec.Debug)
}

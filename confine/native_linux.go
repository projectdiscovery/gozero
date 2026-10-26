//go:build linux

package confine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"

	"github.com/projectdiscovery/gozero/types"
)

// newNativeConfiner returns a bubblewrap confiner when bwrap is on PATH and
// can build a sandbox here, else nil so New fails closed.
func newNativeConfiner(p Policy) Confiner {
	bin, err := exec.LookPath("bwrap")
	if err != nil {
		p.Logger.Debug("confine: bubblewrap unavailable", "reason", "bwrap not found on PATH")
		return nil
	}
	if err := probeBwrap(bin); err != nil {
		p.Logger.Debug("confine: bubblewrap unavailable", "reason", "probe failed", "error", err)
		return nil
	}
	return &bubblewrapConfiner{bin: bin, policy: p}
}

// bwrapProbes caches one probe result per bwrap binary.
var bwrapProbes sync.Map

// probeBwrap runs a trivial command under the same namespaces the payload
// gets. bwrap is often installed where it cannot work: unprivileged
// containers without user namespaces, or a process under Landlock, which
// forbids mount(2). Without the probe, New would succeed and every Run fail.
func probeBwrap(bin string) error {
	if v, ok := bwrapProbes.Load(bin); ok {
		if v == nil {
			return nil
		}
		return v.(error)
	}
	trueBin, err := exec.LookPath("true")
	if err == nil {
		var out []byte
		out, err = exec.Command(bin, "--unshare-all", "--die-with-parent", "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev", "--", trueBin).CombinedOutput()
		if err != nil {
			err = fmt.Errorf("%w: %s", err, out)
		}
	}
	if err == nil {
		bwrapProbes.Store(bin, nil)
		return nil
	}
	bwrapProbes.Store(bin, err)
	return err
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

package confine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dockerOrSkip returns a Docker confiner or skips the test. It only runs where a
// reachable daemon exists (fail-closed New returns an error otherwise), so CI
// hosts without Docker skip cleanly instead of failing. The daemon must also be
// a Linux-container daemon: the confiner uses Linux container semantics (bind
// paths like /gozero-src, tmpfs, --network none), which a Windows-container
// daemon (e.g. the windows-latest runner) rejects, so those hosts skip too.
func dockerOrSkip(t *testing.T) Confiner {
	t.Helper()
	c, err := New(&Policy{Backend: BackendDocker})
	if err != nil {
		t.Skipf("docker confinement unavailable on this host: %v", err)
	}
	dc, ok := c.(*dockerConfiner)
	if !ok {
		_ = c.Close()
		t.Skipf("unexpected confiner type %T", c)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ver, err := dc.cli.ServerVersion(ctx, client.ServerVersionOptions{})
	if err != nil {
		_ = c.Close()
		t.Skipf("docker daemon version unavailable: %v", err)
	}
	if ver.Os != "linux" {
		_ = c.Close()
		t.Skipf("docker daemon is a %q-container daemon; confine targets linux containers", ver.Os)
	}
	return c
}

// dockerCtx gives the first run enough headroom to pull the base image.
func dockerCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 3*time.Minute)
}

func TestDockerConfinedRunProducesOutput(t *testing.T) {
	c := dockerOrSkip(t)
	defer func() { _ = c.Close() }()

	p, data := writeScript(t, "echo docker-hello\n")
	ctx, cancel := dockerCtx(t)
	defer cancel()

	res, err := c.Run(ctx, Spec{Command: []string{"/bin/sh", p}, ScriptPath: p, ScriptData: data})
	require.NoError(t, err)
	assert.Equal(t, "docker-hello", strings.TrimSpace(res.Stdout.String()))
	assert.Equal(t, 0, res.GetExitCode())
}

func TestDockerConfinedPropagatesExitCode(t *testing.T) {
	c := dockerOrSkip(t)
	defer func() { _ = c.Close() }()

	p, data := writeScript(t, "exit 5\n")
	ctx, cancel := dockerCtx(t)
	defer cancel()

	res, _ := c.Run(ctx, Spec{Command: []string{"/bin/sh", p}, ScriptPath: p, ScriptData: data})
	require.NotNil(t, res)
	assert.Equal(t, 5, res.GetExitCode())
}

// TestDockerConfinedStreamsStdin exercises the stdin attach path and the
// stdcopy demux of the multiplexed container stream.
func TestDockerConfinedStreamsStdin(t *testing.T) {
	c := dockerOrSkip(t)
	defer func() { _ = c.Close() }()

	p, data := writeScript(t, "cat\n")
	ctx, cancel := dockerCtx(t)
	defer cancel()

	res, err := c.Run(ctx, Spec{
		Command:    []string{"/bin/sh", p},
		ScriptPath: p,
		ScriptData: data,
		Stdin:      strings.NewReader("piped-input"),
	})
	require.NoError(t, err)
	assert.Equal(t, "piped-input", strings.TrimSpace(res.Stdout.String()))
}

// TestDockerConfinedBlocksNetwork asserts the container runs with no network:
// an outbound connection attempt must fail under the default policy.
func TestDockerConfinedBlocksNetwork(t *testing.T) {
	c := dockerOrSkip(t)
	defer func() { _ = c.Close() }()

	// busybox wget on the default alpine image; -T bounds the attempt so the
	// test fails fast rather than hanging if something is misconfigured.
	p, data := writeScript(t, "wget -q -T 5 -O - http://example.com >/dev/null 2>&1 && echo REACHED || echo BLOCKED\n")
	ctx, cancel := dockerCtx(t)
	defer cancel()

	res, err := c.Run(ctx, Spec{Command: []string{"/bin/sh", p}, ScriptPath: p, ScriptData: data})
	require.NoError(t, err)
	assert.Equal(t, "BLOCKED", strings.TrimSpace(res.Stdout.String()),
		"container reached the network under a network-denied policy")
}

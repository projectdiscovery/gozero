package confine

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nativeOrSkip returns an available native confiner or skips the test. These
// tests exercise the real OS boundary and only run where the mechanism
// (bubblewrap / Seatbelt) is installed.
func nativeOrSkip(t *testing.T) Confiner {
	t.Helper()
	c, err := New(&Policy{Backend: BackendAuto})
	if err != nil {
		t.Skipf("no native confiner available on this host: %v", err)
	}
	return c
}

func writeScript(t *testing.T, body string) (path string, data []byte) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "script.sh")
	data = []byte(body)
	require.NoError(t, os.WriteFile(p, data, 0o600))
	return p, data
}

func TestConfinedRunProducesOutput(t *testing.T) {
	c := nativeOrSkip(t)
	defer func() { _ = c.Close() }()

	p, data := writeScript(t, "echo confined-hello\n")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	res, err := c.Run(ctx, Spec{
		Command:    []string{"/bin/sh", p},
		ScriptPath: p,
		ScriptData: data,
	})
	require.NoError(t, err)
	assert.Equal(t, "confined-hello", strings.TrimSpace(res.Stdout.String()))
	assert.Equal(t, 0, res.GetExitCode())
}

func TestConfinedRunPropagatesExitCode(t *testing.T) {
	c := nativeOrSkip(t)
	defer func() { _ = c.Close() }()

	p, data := writeScript(t, "exit 7\n")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	res, _ := c.Run(ctx, Spec{Command: []string{"/bin/sh", p}, ScriptPath: p, ScriptData: data})
	require.NotNil(t, res)
	assert.Equal(t, 7, res.GetExitCode())
}

// TestConfinedBlocksWriteOutsideWorkspace is the escape assertion: a payload
// must not be able to write outside its workspace/temp. We aim at a file under
// the real user home (neither the workspace nor the system temp dir) and verify
// it is never created.
func TestConfinedBlocksWriteOutsideWorkspace(t *testing.T) {
	c := nativeOrSkip(t)
	defer func() { _ = c.Close() }()

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home dir to target for the escape test")
	}
	escape := filepath.Join(home, ".gozero_confine_escape_probe")
	_ = os.Remove(escape)
	t.Cleanup(func() { _ = os.Remove(escape) })

	p, data := writeScript(t, "echo pwned > \"$ESCAPE_PATH\"\n")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, _ = c.Run(ctx, Spec{
		Command:    []string{"/bin/sh", p},
		ScriptPath: p,
		ScriptData: data,
		Env:        map[string]string{"ESCAPE_PATH": escape},
	})

	_, statErr := os.Stat(escape)
	assert.Truef(t, os.IsNotExist(statErr),
		"payload escaped confinement: wrote %s (statErr=%v)", escape, statErr)
}

// TestConfinedEnvIsScrubbed verifies that an ambient host secret does not reach
// the payload's environment.
func TestConfinedEnvIsScrubbed(t *testing.T) {
	t.Setenv("GOZERO_CONFINE_SECRET", "leak-me")
	c := nativeOrSkip(t)
	defer func() { _ = c.Close() }()

	p, data := writeScript(t, "printf '[%s]' \"$GOZERO_CONFINE_SECRET\"\n")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	res, err := c.Run(ctx, Spec{Command: []string{"/bin/sh", p}, ScriptPath: p, ScriptData: data})
	require.NoError(t, err)
	assert.Equal(t, "[]", strings.TrimSpace(res.Stdout.String()),
		"ambient secret leaked into confined payload")
}

// TestConfinedBlocksNetwork is the network-escape assertion: with the default
// (network-denied) policy a payload must not be able to reach a listening
// socket, even on loopback. We stand up a local TCP server, confirm the client
// technique works unconfined, then assert the confined payload cannot reach it.
func TestConfinedBlocksNetwork(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is required for the /dev/tcp network probe")
	}
	c := nativeOrSkip(t)
	defer func() { _ = c.Close() }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("REACHED\n"))
			_ = conn.Close()
		}
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	// bash's /dev/tcp connects to the listener and echoes whatever it sends.
	p, data := writeScript(t, "exec 3<>/dev/tcp/127.0.0.1/$PORT && cat <&3\n")
	env := map[string]string{"PORT": port}

	// Sanity: unconfined the technique must actually reach the server, otherwise
	// this environment cannot even do loopback and the test proves nothing.
	host, err := New(&Policy{Backend: BackendHost})
	require.NoError(t, err)
	hctx, hcancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer hcancel()
	hres, _ := host.Run(hctx, Spec{Command: []string{bash, p}, ScriptPath: p, ScriptData: data, Env: env})
	if hres == nil || !strings.Contains(hres.Stdout.String(), "REACHED") {
		t.Skip("loopback not reachable even unconfined; cannot assert network denial here")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, _ := c.Run(ctx, Spec{Command: []string{bash, p}, ScriptPath: p, ScriptData: data, Env: env})
	require.NotNil(t, res)
	assert.NotContains(t, res.Stdout.String(), "REACHED",
		"payload reached the network under a network-denied policy")
}

// TestConfinedTimeoutKillsPayload verifies that Policy.Timeout is enforced: a
// long-running payload is killed well before it would finish on its own.
func TestConfinedTimeoutKillsPayload(t *testing.T) {
	c, err := New(&Policy{Backend: BackendAuto, Timeout: 750 * time.Millisecond})
	if err != nil {
		t.Skipf("no native confiner available on this host: %v", err)
	}
	defer func() { _ = c.Close() }()

	p, data := writeScript(t, "sleep 30\n")

	start := time.Now()
	_, err = c.Run(context.Background(), Spec{Command: []string{"/bin/sh", p}, ScriptPath: p, ScriptData: data})
	elapsed := time.Since(start)

	require.Error(t, err, "expected the payload to be killed by the timeout")
	assert.Less(t, elapsed, 10*time.Second,
		"timeout was not enforced; payload ran for %s", elapsed)
}

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

// TestConfinedBlocksWriteToSharedTemp checks that the payload cannot write in
// the host temp dir outside its own workspace, which is shared with other
// processes and with other confined runs.
func TestConfinedBlocksWriteToSharedTemp(t *testing.T) {
	c := nativeOrSkip(t)
	defer func() { _ = c.Close() }()

	escape := filepath.Join(os.TempDir(), "gozero_confine_tmp_probe")
	_ = os.Remove(escape)
	t.Cleanup(func() { _ = os.Remove(escape) })

	p, data := writeScript(t, "echo pwned > \"$ESCAPE_PATH\"\necho ok > \"$HOME/inside\"\ncat \"$HOME/inside\"\n")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	res, _ := c.Run(ctx, Spec{
		Command:    []string{"/bin/sh", p},
		ScriptPath: p,
		ScriptData: data,
		Env:        map[string]string{"ESCAPE_PATH": escape},
	})
	require.NotNil(t, res)
	assert.Contains(t, res.Stdout.String(), "ok", "the workspace must stay writable")

	_, statErr := os.Stat(escape)
	assert.Truef(t, os.IsNotExist(statErr),
		"payload wrote the shared temp dir: %s (statErr=%v)", escape, statErr)
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

// TestConfinedHidesRealHome runs against the real $HOME: the payload must not
// see any entry in it (Seatbelt denies the read, bwrap shows an empty tmpfs)
// and must not read ~/.ssh.
func TestConfinedHidesRealHome(t *testing.T) {
	home := hiddenHome()
	if home == "" {
		t.Skip("no home directory to hide")
	}
	c := nativeOrSkip(t)
	defer func() { _ = c.Close() }()

	p, data := writeScript(t, "ls -A \"$REAL_HOME\" 2>/dev/null | wc -l | tr -d ' '\n"+
		"ls -A \"$REAL_HOME/.ssh\" >/dev/null 2>&1 && echo SSH=readable || echo SSH=denied\n")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := c.Run(ctx, Spec{Command: []string{"/bin/sh", p}, ScriptPath: p, ScriptData: data, Env: map[string]string{"REAL_HOME": home}})
	require.NoError(t, err)
	out := strings.Fields(res.Stdout.String())
	require.Len(t, out, 2, "unexpected output: %q", res.Stdout.String())
	assert.Equal(t, "0", out[0], "home must look empty inside the sandbox")
	assert.Equal(t, "SSH=denied", out[1])
}

// TestConfinedHomeAllowList checks that only ReadOnlyPaths entries under $HOME
// are readable, and that they stay read-only.
func TestConfinedHomeAllowList(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".secret"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".secret", "key"), []byte("TOPSECRET"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".pyenv", "bin"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".pyenv", "bin", "tool"), []byte("ALLOWED"), 0o644))

	c, err := New(&Policy{Backend: BackendAuto, ReadOnlyPaths: []string{"~/.pyenv"}})
	if err != nil {
		t.Skipf("no native confiner available on this host: %v", err)
	}
	defer func() { _ = c.Close() }()

	p, data := writeScript(t, "cat \"$H/.pyenv/bin/tool\" 2>/dev/null || echo NO_TOOL\n"+
		"cat \"$H/.secret/key\" 2>/dev/null || echo NO_SECRET\n"+
		"echo x > \"$H/.pyenv/bin/tool\" 2>/dev/null && echo WROTE || echo RO\n")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := c.Run(ctx, Spec{Command: []string{"/bin/sh", p}, ScriptPath: p, ScriptData: data, Env: map[string]string{"H": canonicalPath(home)}})
	require.NoError(t, err)
	out := res.Stdout.String()
	assert.Contains(t, out, "ALLOWED", "allow-listed home path must be readable")
	assert.Contains(t, out, "NO_SECRET", "other home paths must stay hidden")
	assert.NotContains(t, out, "TOPSECRET")
	assert.Contains(t, out, "RO", "allow-listed path must be read-only")
}

// TestConfinedHidesSystemDirs checks the dirs hidden besides the user's home:
// other users' homes, root's home and (Linux) the runtime socket dirs. The
// payload must see none of their entries.
func TestConfinedHidesSystemDirs(t *testing.T) {
	roots := hiddenRoots()
	if len(roots) == 0 {
		t.Skip("no hidden dirs on this platform")
	}
	c := nativeOrSkip(t)
	defer func() { _ = c.Close() }()

	var body strings.Builder
	for _, root := range roots {
		body.WriteString("echo \"" + root + "=$(ls -A '" + root + "' 2>/dev/null | wc -l | tr -d ' ')\"\n")
	}
	p, data := writeScript(t, body.String())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := c.Run(ctx, Spec{Command: []string{"/bin/sh", p}, ScriptPath: p, ScriptData: data})
	require.NoError(t, err)
	for _, root := range roots {
		assert.Contains(t, res.Stdout.String(), root+"=0\n", "%s must look empty inside the sandbox", root)
	}
}

package confine

import (
	"context"
	"os"
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

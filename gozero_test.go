package gozero

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/projectdiscovery/gozero/confine"
	"github.com/projectdiscovery/gozero/types"
	osutils "github.com/projectdiscovery/utils/os"
	"github.com/stretchr/testify/require"
)

func TestEval(t *testing.T) {
	opts := &Options{}
	if osutils.IsWindows() {
		opts.Engines = []string{"python3.exe"}
	} else {
		opts.Engines = []string{"python3"}
	}
	pyzero, err := New(opts)
	require.Nil(t, err)
	src, err := NewSourceWithString(`print(1)`, "", "")
	require.Nil(t, err)
	// empty input
	input, err := NewSource()
	require.Nil(t, err)
	out, err := pyzero.Eval(context.Background(), src, input)
	require.Nil(t, err)
	output := out.Stdout.String()
	require.Equal(t, "1", strings.TrimSpace(string(output)))
	err = src.Cleanup()
	require.Nil(t, err)
	err = input.Cleanup()
	require.Nil(t, err)
}

func TestErr(t *testing.T) {
	opts := &Options{}
	if osutils.IsWindows() {
		opts.Engines = []string{"nonexistent.exe"}
	} else {
		opts.Engines = []string{"nonexistent"}
	}
	gozero, err := New(opts)
	require.NotNil(t, err)
	require.Nil(t, gozero)
	require.ErrorIs(t, err, ErrNoValidEngine)

	opts.Engines = []string{}
	gozero, err = New(opts)
	require.NotNil(t, err)
	require.Nil(t, gozero)
	require.ErrorIs(t, err, ErrNoEngines)

	opts.Engines = []string{"python3"}
	gozero, err = New(opts)
	require.Nil(t, err)
	require.NotNil(t, gozero)
}

// TestNewFailsClosedWhenConfinementUnavailable asserts the anti-escape
// contract at the executor boundary: if confinement is requested but the
// backend cannot be established, New refuses to hand back an executor, so it is
// impossible to reach Eval and then run unconfined.
func TestNewFailsClosedWhenConfinementUnavailable(t *testing.T) {
	opts := &Options{
		Engines:     []string{"sh"},
		Sandbox:     true,
		Confinement: &confine.Policy{Backend: confine.Backend("does-not-exist")},
	}
	g, err := New(opts)
	require.Error(t, err)
	require.Nil(t, g)
}

// TestEvalSandboxed runs a real confined execution end-to-end through the
// executor when a native confiner is available (skipped otherwise).
func TestEvalSandboxed(t *testing.T) {
	if osutils.IsWindows() {
		t.Skip("native confinement not implemented on windows")
	}
	opts := &Options{Engines: []string{"sh"}, Sandbox: true}
	g, err := New(opts)
	if err != nil {
		t.Skipf("no native confiner available: %v", err)
	}
	defer func() { _ = g.Close() }()

	src, err := NewSourceWithString("echo sandboxed-ok\n", "", "")
	require.Nil(t, err)
	defer func() { _ = src.Cleanup() }()
	input, err := NewSource()
	require.Nil(t, err)
	defer func() { _ = input.Cleanup() }()

	out, err := g.Eval(context.Background(), src, input)
	require.Nil(t, err)
	require.Equal(t, "sandboxed-ok", strings.TrimSpace(out.Stdout.String()))
}

// TestEvalSandboxedPythonHidesHome runs python3 through Eval with Sandbox on:
// the interpreter must still start, and the real $HOME (e.g. ~/.ssh) must not
// be readable from the payload.
func TestEvalSandboxedPythonHidesHome(t *testing.T) {
	if osutils.IsWindows() {
		t.Skip("native confinement not implemented on windows")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "/" {
		t.Skip("no home directory to hide")
	}
	g, err := New(&Options{Engines: []string{"python3"}, Sandbox: true})
	if err != nil {
		t.Skipf("no native confiner or python3: %v", err)
	}
	defer func() { _ = g.Close() }()

	src, err := NewSourceWithString(`import os, sys
print("py", sys.version_info[0])
for p in (os.environ["REAL_HOME"], os.path.join(os.environ["REAL_HOME"], ".ssh")):
    try:
        print("listed", len(os.listdir(p)))
    except OSError as e:
        print("denied", e.errno)
`, "", "")
	require.Nil(t, err)
	defer func() { _ = src.Cleanup() }()
	src.AddVariable(types.Variable{Name: "REAL_HOME", Value: home})
	input, err := NewSource()
	require.Nil(t, err)
	defer func() { _ = input.Cleanup() }()

	out, err := g.Eval(context.Background(), src, input)
	require.Nil(t, err)
	got := out.Stdout.String()
	t.Log(got)
	require.Contains(t, got, "py 3")
	require.NotRegexp(t, `listed [1-9]`, got, "home entries must not be visible")
}

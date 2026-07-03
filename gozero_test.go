package gozero

import (
	"context"
	"strings"
	"testing"

	"github.com/projectdiscovery/gozero/confine"
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

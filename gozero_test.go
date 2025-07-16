package gozero

import (
	"context"
	"strings"
	"testing"

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

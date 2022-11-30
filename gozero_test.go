package gozero

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEval(t *testing.T) {
	opts := PythonDefaultOptions
	opts.Engine = "python3"
	pyzero, err := New(opts)
	require.Nil(t, err)
	src, err := NewSourceWithString(`print(1)`)
	require.Nil(t, err)
	// empty input
	input, err := NewSource()
	require.Nil(t, err)
	out, err := pyzero.Eval(src, input)
	require.Nil(t, err)
	output, err := out.ReadAll()
	require.Nil(t, err)
	require.Equal(t, strings.TrimSpace(string(output)), "1")
	err = src.Cleanup()
	require.Nil(t, err)
	err = input.Cleanup()
	require.Nil(t, err)
	err = out.Cleanup()
	require.Nil(t, err)
}

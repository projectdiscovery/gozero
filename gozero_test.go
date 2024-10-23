package gozero

import (
	"context"
	"strings"
	"testing"

	// osutils "github.com/projectdiscovery/utils/os"
	osutils "github.com/projectdiscovery/utils/os"
	"github.com/stretchr/testify/require"
)

func TestEvalPython(t *testing.T) {
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

func TestEvalGo(t *testing.T) {
	opts := &Options{}
	opts.Engines = []string{"go"}
	opts.Args = []string{"run"}
	gzero, err := New(opts)
	require.Nil(t, err)
	src, err := NewSourceWithString(`
      package main

      import "fmt"

      func main() {
          fmt.Println("hello world")
      }
      `,
		"*.go", "")
	require.Nil(t, err)
	// empty input
	input, err := NewSource()
	require.Nil(t, err)
	out, err := gzero.Eval(context.Background(), src, input, opts.Args...)
	require.Nil(t, err)
	output := out.Stdout.String()
	require.Equal(t, "hello world", strings.TrimSpace(string(output)))
	err = src.Cleanup()
	require.Nil(t, err)
	err = input.Cleanup()
	require.Nil(t, err)
}

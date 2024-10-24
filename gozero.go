package gozero

import (
	"context"
	"errors"
	"fmt"
	"os/exec"

	"github.com/projectdiscovery/gozero/cmdexec"
	"github.com/projectdiscovery/gozero/types"
)

// Gozero is executor for gozero
type Gozero struct {
	Options *Options
}

// New creates a new gozero executor
func New(options *Options) (*Gozero, error) {
	if len(options.Engines) == 0 {
		return nil, errors.New("no engines provided")
	}
	// attempt to locate the interpreter by executing it
	for _, engine := range options.Engines {
		// use lookpath to check if engine is available
		// this ignores path confusion issues where binary with same name exists in current path
		fpath, err := exec.LookPath(engine)
		if err != nil {
			fmt.Printf("engine %s not found: %v\n", engine, err)
			continue
		} else {
			options.engine = fpath
			break
		}
	}
	if options.engine == "" {
		return nil, errors.New("no valid engine found")
	}
	return &Gozero{Options: options}, nil
}

// Eval evaluates the source code and returns the output
// input = stdin , src = source code , args = arguments
func (g *Gozero) Eval(ctx context.Context, src, input *Source, args ...string) (*types.Result, error) {
	if g.Options.EarlyCloseFileDescriptor {
		src.File.Close()
	}
	allargs := []string{}
	allargs = append(allargs, g.Options.Args...)
	allargs = append(allargs, src.Filename)
	allargs = append(allargs, args...)
	gcmd, err := cmdexec.NewCommand(g.Options.engine, allargs...)
	if err != nil {
		// returns error if binary(engine) does not exist
		return nil, err
	}
	gcmd.SetStdin(input.File) // stdin
	// add both input and src variables if any
	gcmd.AddVars(src.Variables...) // variables as environment variables
	gcmd.AddVars(input.Variables...)
	return gcmd.Execute(ctx)
}

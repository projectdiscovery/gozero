package gozero

import (
	"context"
	"errors"
	"os"
	"os/exec"

	"github.com/projectdiscovery/gozero/sandbox"
)

type Gozero struct {
	Options *Options
}

func New(options *Options) (*Gozero, error) {
	return &Gozero{Options: options}, nil
}

func (g *Gozero) ExecWithSandbox(ctx context.Context, input *Source, cmd *Command) (*Source, error) {
	// check if the sandbox functionality is supported
	ok, err := sandbox.IsEnabled(ctx)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, errors.New("sandbox mode not supported")
	}

	// mount all sources into mounted folders
	output, err := NewSource()
	if err != nil {
		return nil, err
	}

	sharedFolders := []sandbox.MappedFolder{
		// input
		{HostFolder: input.Filename, ReadOnly: true},
		// output
		{HostFolder: output.Filename},
		// cmd - mount the binary folder as read-only
		{HostFolder: cmd.Name, ReadOnly: true},
	}

	sandboxConfig := sandbox.Config{
		MappedFolders: sharedFolders,
		Networking:    sandbox.Enable,
	}
	gSandbox, err := sandbox.New(ctx, &sandboxConfig)
	if err != nil {
		return output, nil
	}
	_ = gSandbox.Run(ctx)
	//todo: download a helium pipeglue within the sandbox and glue stdin/stout via networking

	return output, errors.New("partially implemented")
}

func (g *Gozero) Exec(ctx context.Context, input *Source, cmd *Command) (*Source, error) {
	output, err := NewSource()
	if err != nil {
		return nil, err
	}
	gCmd := exec.CommandContext(ctx, cmd.Name, cmd.Args...)
	gCmd.Stdin = input.File
	gCmd.Stdout = output.File
	return output, gCmd.Run()
}

func (g *Gozero) Eval(ctx context.Context, src, input *Source, args ...string) (*Source, error) {
	output, err := NewSource()
	if err != nil {
		return nil, err
	}
	switch {
	case g.Options.PreferStartProcess:
		err = g.runWithApi(ctx, src, input, output, args...)
	default:
		err = g.run(ctx, src, input, output, args...)
	}
	if err != nil {
		return nil, err
	}
	return output, nil
}

func (g *Gozero) run(ctx context.Context, src, input, output *Source, args ...string) error {
	cmdArgs := []string{src.Filename}
	cmdArgs = append(cmdArgs, args...)
	gCmd := exec.CommandContext(ctx, g.Options.Engine, cmdArgs...)
	gCmd.Stdin = input.File
	gCmd.Stdout = output.File
	return gCmd.Run()
}

func (g *Gozero) runWithApi(ctx context.Context, src, input, output *Source, args ...string) error {
	var procAttr os.ProcAttr
	cmdArgs := []string{g.Options.Engine, src.Filename}
	cmdArgs = append(cmdArgs, args...)
	procAttr.Files = []*os.File{input.File, output.File, nil}
	proc, err := os.StartProcess(g.Options.Engine, cmdArgs, &procAttr)
	if err != nil {
		return err
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				proc.Kill()
				return
			default:
			}
		}
	}()

	if _, err = proc.Wait(); err != nil {
		return err
	}

	return nil
}

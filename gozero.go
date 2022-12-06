package gozero

import (
	"context"
	"os"
	"os/exec"
)

type Gozero struct {
	Options *Options
}

func New(options *Options) (*Gozero, error) {
	return &Gozero{Options: options}, nil
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

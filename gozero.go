package gozero

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"time"

	"github.com/projectdiscovery/gozero/command"
	errorutil "github.com/projectdiscovery/utils/errors"
)

type Gozero struct {
	Options *Options
}

func New(options *Options) (*Gozero, error) {
	// attempt to locate the interpreter by executing it
	for _, engine := range options.Engines {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, engine)
		err := cmd.Run()
		if err == nil || errorutil.IsAny(err, exec.ErrWaitDelay) {
			options.engine = engine
			break
		}
	}
	if options.engine == "" {
		return nil, errors.New("no valid engine found")
	}
	return &Gozero{Options: options}, nil
}

func (g *Gozero) Exec(ctx context.Context, input *Source, cmd *command.Command) (*Source, error) {
	output, err := NewSource()
	if err != nil {
		return nil, err
	}
	gCmd := exec.CommandContext(ctx, cmd.Name, cmd.Args...)
	gCmd.Stdin = input.File
	gCmd.Stdout = output.File
	gCmd.Env = extendWithVars(gCmd.Environ(), input.Variables...)

	return output, gCmd.Run()
}

func (g *Gozero) Eval(ctx context.Context, src, input *Source, args ...string) (*Source, error) {
	output, err := NewSource()
	if err != nil {
		return nil, err
	}
	if g.Options.EarlyCloseFileDescriptor {
		src.File.Close()
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
	var cmdArgs []string
	cmdArgs = append(cmdArgs, g.Options.Args...)
	cmdArgs = append(cmdArgs, src.Filename)
	cmdArgs = append(cmdArgs, args...)
	gCmd := exec.CommandContext(ctx, g.Options.engine, cmdArgs...)
	gCmd.Stdin = input.File
	gCmd.Stdout = output.File
	gCmd.Env = extendWithVars(gCmd.Environ(), input.Variables...)
	return gCmd.Run()
}

func (g *Gozero) runWithApi(ctx context.Context, src, input, output *Source, args ...string) error {
	var procAttr os.ProcAttr
	cmdArgs := []string{g.Options.engine}
	cmdArgs = append(cmdArgs, g.Options.Args...)
	cmdArgs = append(cmdArgs, src.Filename)
	cmdArgs = append(cmdArgs, args...)
	procAttr.Files = []*os.File{input.File, output.File, nil}
	procAttr.Env = extendWithVars(procAttr.Env, input.Variables...)
	proc, err := os.StartProcess(g.Options.engine, cmdArgs, &procAttr)
	if err != nil {
		return err
	}

	go func() {
		for range ctx.Done() {
			proc.Kill()
			return
		}
	}()

	if _, err = proc.Wait(); err != nil {
		return err
	}

	return nil
}

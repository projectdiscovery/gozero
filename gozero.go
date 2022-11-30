package gozero

import (
	"os"
	"os/exec"
)

type Gozero struct {
	Options *Options
}

func New(options *Options) (*Gozero, error) {
	return &Gozero{Options: options}, nil
}

func (g *Gozero) Eval(src, input *Source) (*Source, error) {
	output, err := NewSource()
	if err != nil {
		return nil, err
	}
	switch {
	case g.Options.PreferStartProcess:
		err = g.runWithApi(src, input, output)
	default:
		err = g.run(src, input, output)
	}
	if err != nil {
		return nil, err
	}
	return output, nil
}

func (g *Gozero) run(src, input, output *Source) error {
	pyCmd := exec.Command(g.Options.Engine, src.Filename)
	pyCmd.Stdin = input.File
	pyCmd.Stdout = output.File
	return pyCmd.Run()
}

func (g *Gozero) runWithApi(src, input, output *Source) error {
	var procAttr os.ProcAttr
	procAttr.Files = []*os.File{input.File, output.File, nil}
	proc, err := os.StartProcess(g.Options.Engine, []string{g.Options.Engine, src.Filename}, &procAttr)
	if err != nil {
		return err
	}

	if _, err = proc.Wait(); err != nil {
		return err
	}

	return nil
}

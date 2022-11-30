package gozero

import (
	"os"
	"os/exec"
)

type Pyzero struct {
	Options *Options
}

func New(options *Options) (*Pyzero, error) {
	return &Pyzero{Options: options}, nil
}

func (py *Pyzero) Eval(pyfile, input *Source) (*Source, error) {
	output, err := NewSource()
	if err != nil {
		return nil, err
	}
	switch {
	case py.Options.PreferStartProcess:
		err = py.runWithApi(pyfile, input, output)
	default:
		err = py.run(pyfile, input, output)
	}
	if err != nil {
		return nil, err
	}
	return output, nil
}

func (py *Pyzero) run(pyfile, input, output *Source) error {
	pyCmd := exec.Command(py.Options.Engine, pyfile.Filename)
	pyCmd.Stdin = input.File
	pyCmd.Stdout = output.File
	return pyCmd.Run()
}

func (py *Pyzero) runWithApi(pyfile, input, output *Source) error {
	var procAttr os.ProcAttr
	procAttr.Files = []*os.File{input.File, output.File, nil}
	proc, err := os.StartProcess(py.Options.Engine, []string{py.Options.Engine, pyfile.Filename}, &procAttr)
	if err != nil {
		return err
	}

	if _, err = proc.Wait(); err != nil {
		return err
	}

	return nil
}

package gozero

import "strings"

type Command struct {
	Name string
	Args []string
}

func NewCommand() (*Command, error) {
	return NewCommandWithString("")
}

func NewCommandWithString(name string, args ...string) (*Command, error) {
	name = strings.TrimSpace(name)
	return &Command{Name: name, Args: args}, nil
}

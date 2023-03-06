//go:build darwin

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Configuration struct {
	Rules []Rule
}

type Action string

const (
	Allow Action = "allow"
	Deny  Action = "deny"
)

type Scope string

const (
	Network   Scope = "network"
	FileWrite Scope = "file-write"
	FileRead  Scope = "file-read"
	Process   Scope = "process"
	Default   Scope = "default"
)

type ArgsType string

const (
	LocalIP  = `local ip "%s"`
	RemoteIP = `local ip "%s"`
	SubPath  = `subpath "%s"`
)

type Rule struct {
	Action Action
	Scope  Scope
	Args   []Arg
}

type Arg struct {
	Type   ArgsType
	Params []any
}

// Sandbox native on windows
type SandboxDarwin struct {
	Config   *Configuration
	confFile string
}

// New sandbox with the given configuration
func New(ctx context.Context, config *Configuration) (Sandbox, error) {
	if ok, err := IsInstalled(context.Background()); err != nil || !ok {
		return nil, errors.New("sandbox feature not installed")
	}

	sharedFolder, err := os.MkdirTemp("", "")
	if err != nil {
		return nil, err
	}

	sharedFolder = filepath.Join(sharedFolder, "gozero")

	if err := os.MkdirAll(sharedFolder, 0600); err != nil {
		return nil, err
	}

	confFile := filepath.Join(sharedFolder, "config.sb")

	var confData bytes.Buffer
	confData.WriteString("(version 1\n")
	confData.WriteString("(debug deny)\n")
	confData.WriteString("(allow default)\n")
	for _, rule := range config.Rules {
		if rule.Action != "" {
			confData.WriteString("(" + string(rule.Action) + " ")
		}
		if rule.Scope != "" {
			confData.WriteString(string(rule.Scope) + "* ")
		}
		for _, arg := range rule.Args {
			confData.WriteString(fmt.Sprintf("("+string(arg.Type)+")", arg.Params...))
		}
	}
	if err := os.WriteFile(confFile, confData.Bytes(), 0600); err != nil {
		return nil, err
	}

	s := &SandboxDarwin{Config: config, confFile: confFile}
	return s, nil
}

func (s *SandboxDarwin) Run(ctx context.Context, cmd string) error {
	params := []string{"-f", s.confFile}
	params = append(params, strings.Split(cmd, " ")...)
	cmdContext := exec.CommandContext(ctx, "sandbox-exec", params...)
	var stdout, stderr bytes.Buffer
	cmdContext.Stdout = &stdout
	cmdContext.Stderr = &stderr
	return cmdContext.Run()
}

// Start the instance
func (s *SandboxDarwin) Start() error {
	return errors.New("not implemented")
}

// Wait for the instance
func (s *SandboxDarwin) Wait() error {
	return errors.New("not implemented")
}

// Stop the instance
func (s *SandboxDarwin) Stop() error {
	return errors.New("not implemented")
}

// Clear the instance after stop
func (s *SandboxDarwin) Clear() error {
	return os.RemoveAll(s.confFile)
}

func isEnabled(ctx context.Context) (bool, error) {
	return isInstalled(ctx)
}

func isInstalled(ctx context.Context) (bool, error) {
	_, err := exec.LookPath("sandbox-exec")
	if err != nil {
		return false, err
	}
	return true, nil
}

func activate(ctx context.Context) (bool, error) {
	return false, errors.New("sandbox is a darwin native functionality")
}

func deactvate(ctx context.Context) (bool, error) {
	return false, errors.New("sandbox can't be disabled")
}

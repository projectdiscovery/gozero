//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os/exec"
	"strings"

	"github.com/projectdiscovery/gozero/cmdexec"
	"github.com/projectdiscovery/gozero/types"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

type Configuration struct {
	Rules []Rule
}

type Filter string

const (
	PrivateTmp              Filter = "PrivateTmp"
	PrivateNetwork          Filter = "PrivateNetwork"
	SELinuxContext          Filter = "SELinuxContext"
	NoNewPrivileges         Filter = "NoNewPrivileges"
	ProtectSystem           Filter = "ProtectSystem"
	ProtectHome             Filter = "ProtectHome"
	ProtectDevices          Filter = "ProtectDevices"
	CapabilityBoundingSet   Filter = "CapabilityBoundingSet"
	ReadWriteDirectories    Filter = "ReadWriteDirectories"
	ReadOnlyDirectories     Filter = "ReadOnlyDirectories"
	InaccessibleDirectories Filter = "InaccessibleDirectories"
	ProtectKernelTunables   Filter = "InaccessibleDirectories"
	ProtectKernelModules    Filter = "ProtectKernelModules"
	ProtectControlGroups    Filter = "ProtectControlGroups"
	RestrictNamespaces      Filter = "RestrictNamespaces"
	MemoryDenyWriteExecute  Filter = "MemoryDenyWriteExecute"
	RestrictRealtime        Filter = "RestrictRealtime"
	PrivateMounts           Filter = "PrivateMounts"
	DynamicUser             Filter = "DynamicUser"
	SystemCallFilter        Filter = "SystemCallFilter"
)

type ArgsType uint8

const (
	Bool ArgsType = iota
	Folders
	Capabilities
	Namespaces
	SystemCalls
)

type Arg struct {
	Type   ArgsType
	Params interface{}
}

type Rule struct {
	Filter Filter
	Arg    Arg
}

// Sandbox native on linux
type SandboxLinux struct {
	Config *Configuration
	conf   []string
}

// New sandbox with the given configuration
func New(ctx context.Context, config *Configuration) (Sandbox, error) {
	if ok, err := IsInstalled(context.Background()); err != nil || !ok {
		return nil, errors.New("sandbox feature not installed")
	}

	conf := []string{"--pipe", "--pty", "--user"}
	for _, rule := range config.Rules {
		var actionArgs []string
		if rule.Filter == "" {
			return nil, errors.New("empty action")
		}
		actionArgs = append(actionArgs, "-p")
		switch rule.Arg.Type {
		case Bool:
			v, ok := rule.Arg.Params.(string)
			if !ok {
				return nil, errors.New("invalid string value")
			}
			if !stringsutil.EqualFoldAny(v, "yes", "no") {
				return nil, errors.New("invalid value (yes/no)")
			}
			actionArgs = append(actionArgs, string(rule.Filter)+"="+v)
		case Folders, Capabilities, Namespaces, SystemCalls:
			v, ok := rule.Arg.Params.([]string)
			if !ok {
				return nil, errors.New("invalid string value")
			}
			actionArgs = append(actionArgs, string(rule.Filter)+"="+strings.Join(v, ","))
		default:
			return nil, errors.New("unsupported type")
		}
		conf = append(conf, actionArgs...)
	}

	s := &SandboxLinux{Config: config, conf: conf}
	return s, nil
}

func (s *SandboxLinux) Run(ctx context.Context, cmd string) (*types.Result, error) {
	var params []string
	params = append(params, s.conf...)
	params = append(params, strings.Split(cmd, " ")...)
	cmdContext, err := cmdexec.NewCommand("systemd-run", params...)
	return cmdContext.Execute(ctx)
}

// Start the instance
func (s *SandboxLinux) Start() error {
	return ErrNotImplemented
}

// Wait for the instance
func (s *SandboxLinux) Wait() error {
	return ErrNotImplemented
}

// Stop the instance
func (s *SandboxLinux) Stop() error {
	return ErrNotImplemented
}

// Clear the instance after stop
func (s *SandboxLinux) Clear() error {
	return ErrNotImplemented
}

func isEnabled(ctx context.Context) (bool, error) {
	return isInstalled(ctx)
}

func isInstalled(ctx context.Context) (bool, error) {
	_, err := exec.LookPath("systemd-run")
	if err != nil {
		return false, err
	}
	return true, nil
}

func activate(ctx context.Context) (bool, error) {
	return false, errors.New("sandbox is a linux native functionality")
}

func deactivate(ctx context.Context) (bool, error) {
	return false, errors.New("can't be disabled")
}

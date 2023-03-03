//go:build windows

package sandbox

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"os"
	"os/exec"
	"regexp"

	fileutil "github.com/projectdiscovery/utils/file"
)

type Value string

const (
	Enable  Value = "Enable"
	Disable Value = "Disable"
	Default Value = "Default"
)

type Config struct {
	MappedFolders   []MappedFolder `xml:"MappedFolders"`
	Networking      Value          `xml:"Networking"`
	LogonCommand    string         `xml:"LogonCommand"`
	VirtualGPU      Value          `xml:"vGPU"`
	ProtectedClient Value          `xml:"ProtectedClient"`
	MemoryInMB      int            `xml:"MemoryInMB"`
}

type MappedFolder struct {
	HostFolder    string `xml:"HostFolder"`
	SandboxFolder string `xml:"SandboxFolder"`
	ReadOnly      bool   `xml:"ReadOnly"`
}

type Sandbox struct {
	Config   *Config
	confFile string
	instance *exec.Cmd
	stdout   bytes.Buffer
	stderr   bytes.Buffer
}

func New(ctx context.Context, config *Config) (*Sandbox, error) {
	if ok, err := IsInstalled(context.Background()); err != nil || !ok {
		return nil, errors.New("sandbox feature not installed")
	}

	confFile, err := fileutil.GetTempFileName()
	if err != nil {
		return nil, err
	}
	data, err := xml.Marshal(config)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(confFile, data, 0600); err != nil {
		return nil, err
	}

	s := &Sandbox{Config: config, confFile: confFile}
	s.instance = exec.CommandContext(ctx, s.confFile)
	s.instance.Stdout = &s.stdout
	s.instance.Stderr = &s.stderr

	return s, nil
}

func (s *Sandbox) Run(ctx context.Context) error {
	return s.instance.Run()
}

func (s *Sandbox) Start() error {
	return s.instance.Start()
}

func (s *Sandbox) Wait() error {
	return s.instance.Wait()
}

func (s *Sandbox) Stop() error {
	err := s.instance.Cancel()
	if err != nil {
		return err
	}
	s.instance = nil
	return nil
}

func (s *Sandbox) Clear() error {
	if err := s.Stop(); err != nil {
		return err
	}
	if err := os.RemoveAll(s.confFile); err != nil {
		return err
	}
	return nil
}

func shellExec(ctx context.Context, args ...string) (string, string, error) {
	powershellPath, err := exec.LookPath("powershell")
	if err != nil {
		return "", "", err
	}
	cmd := exec.CommandContext(ctx, powershellPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	return stdout.String(), stderr.String(), err
}

func IsEnabled(ctx context.Context) (bool, error) {
	stdout, _, err := shellExec(ctx, "Get-WindowsOptionalFeature", "-FeatureName", `"Containers-DisposableClientVM"`, "-Online")
	if err != nil {
		return false, err
	}

	return regexp.MatchString(`(?m)State\s*:\s*Enabled`, stdout)
}

func IsInstalled(ctx context.Context) (bool, error) {
	_, err := exec.LookPath("WindowsSandbox.exe")
	if err != nil {
		return false, err
	}
	return true, nil
}

func Activate(ctx context.Context) (bool, error) {
	_, _, err := shellExec(ctx, "Enable-WindowsOptionalFeature", "-FeatureName", `"Containers-DisposableClientVM"`, "-NoRestart", "True")
	if err != nil {
		return false, err
	}

	return true, nil
}

func Deactivate(ctx context.Context) (bool, error) {
	_, _, err := shellExec(ctx, "Disable-WindowsOptionalFeature", "-FeatureName", `"Containers-DisposableClientVM"`, "-Online")
	if err != nil {
		return false, err
	}

	return true, nil
}

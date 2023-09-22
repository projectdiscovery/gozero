//go:build !(darwin || linux || windows)

package sandbox

import (
	"context"

	"github.com/projectdiscovery/gozero/types"
)

type Configuration struct {
	Rules []Rule
}

type Rule struct{}

// Sandbox native on other platforms
type SandboxOther struct {
	Config *Configuration
	conf   []string
}

// New sandbox with the given configuration
func New(ctx context.Context, config *Configuration) (Sandbox, error) {
	return nil, ErrNotImplemented
}

func (s *SandboxOther) Run(ctx context.Context, cmd string) (*types.Result, error) {
	return nil, ErrNotImplemented
}

// Start the instance
func (s *SandboxOther) Start() error {
	return ErrNotImplemented
}

// Wait for the instance
func (s *SandboxOther) Wait() error {
	return ErrNotImplemented
}

// Stop the instance
func (s *SandboxOther) Stop() error {
	return ErrNotImplemented
}

// Clear the instance after stop
func (s *SandboxOther) Clear() error {
	return ErrNotImplemented
}

func isEnabled(ctx context.Context) (bool, error) {
	return false, ErrNotImplemented
}

func isInstalled(ctx context.Context) (bool, error) {
	return false, ErrNotImplemented
}

func activate(ctx context.Context) (bool, error) {
	return false, ErrNotImplemented
}

func deactivate(ctx context.Context) (bool, error) {
	return false, ErrNotImplemented
}

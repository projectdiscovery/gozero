package sandbox

import (
	"context"

	"github.com/projectdiscovery/gozero/types"
)

func IsEnabled(ctx context.Context) (bool, error) {
	return isEnabled(ctx)
}

func IsInstalled(ctx context.Context) (bool, error) {
	return isInstalled(ctx)
}

func Activate(ctx context.Context) (bool, error) {
	return activate(ctx)
}

func Deactivate(ctx context.Context) (bool, error) {
	return deactivate(ctx)
}

// IsDockerEnabled checks if Docker sandbox is available
func IsDockerEnabled(ctx context.Context) (bool, error) {
	return isDockerEnabled(ctx)
}

// IsDockerInstalled checks if Docker is installed
func IsDockerInstalled(ctx context.Context) (bool, error) {
	return isDockerInstalled(ctx)
}

// ActivateDocker attempts to start Docker daemon
func ActivateDocker(ctx context.Context) (bool, error) {
	return activateDocker(ctx)
}

// DeactivateDocker attempts to stop Docker daemon
func DeactivateDocker(ctx context.Context) (bool, error) {
	return deactivateDocker(ctx)
}

type Sandbox interface {
	Run(ctx context.Context, cmd string) (*types.Result, error)
	RunScript(ctx context.Context, source string) (*types.Result, error)
	RunSource(ctx context.Context, source string) (*types.Result, error)
	Start() error
	Wait() error
	Stop() error
	Clear() error
}

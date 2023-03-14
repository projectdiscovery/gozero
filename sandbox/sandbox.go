package sandbox

import (
	"context"

	"github.com/projectdiscovery/gozero/command"
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

type Sandbox interface {
	Run(ctx context.Context, cmd string) (*command.Result, error)
	Start() error
	Wait() error
	Stop() error
	Clear() error
}

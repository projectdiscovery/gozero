//go:build darwin
// +build darwin

package main

import (
	"context"
	"log"
	"time"

	"github.com/projectdiscovery/gozero/sandbox"
)

func main() {
	command := "hostname"
	rules := []sandbox.Rule{
		{Action: sandbox.Deny, Scope: sandbox.FileWrite},
		{Action: sandbox.Allow, Scope: sandbox.FileWrite, Args: []sandbox.Arg{
			{Type: sandbox.SubPath, Params: []any{"/tmp"}},
		}},
	}
	cfg := sandbox.Configuration{
		Rules: rules,
	}

	instance, err := sandbox.New(context.Background(), &cfg)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := instance.Run(context.Background(), command); err != nil {
		log.Fatal(err)
	}

	time.Sleep(60 * time.Second)
	instance.Clear()
}

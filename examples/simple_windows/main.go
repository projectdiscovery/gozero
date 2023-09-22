//go:build windows
// +build windows

package main

import (
	"context"
	"log"
	"time"

	"github.com/projectdiscovery/gozero/sandbox"
)

func main() {
	commands := []string{
		"ipconfig",
	}
	cfg := sandbox.Configuration{
		Networking: sandbox.Enable,
		VirtualGPU: sandbox.Default,
		MemoryInMB: 500,
	}
	cfg.LogonCommands.Command = commands

	instance, err := sandbox.New(context.Background(), &cfg)
	if err != nil {
		log.Fatal(err)
	}

	if err := instance.Start(); err != nil {
		log.Fatal(err)
	}

	time.Sleep(60 * time.Second)
	instance.Clear()
}

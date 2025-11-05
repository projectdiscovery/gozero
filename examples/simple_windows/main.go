//go:build windows
// +build windows

package main

import (
	"context"
	"log"
	"time"

	"github.com/projectdiscovery/gozero/sandbox"
	osutil "github.com/projectdiscovery/utils/os"
)

func main() {
	if !osutil.IsWindows() {
		log.Printf("This example is only supported on Windows")
		return
	}
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

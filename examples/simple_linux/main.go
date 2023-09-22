//go:build linux
// +build linux

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
		{Filter: sandbox.DynamicUser, Arg: sandbox.Arg{Type: sandbox.Bool, Params: "yes"}},
		{Filter: sandbox.ReadOnlyDirectories, Arg: sandbox.Arg{Type: sandbox.Folders, Params: []string{"/etc", "/home"}}},
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
}

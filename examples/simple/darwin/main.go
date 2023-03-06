package main

import (
	"context"
	"log"
	"time"

	"github.com/projectdiscovery/gozero/sandbox"
)

func main() {
	command := "ifconfig"
	rules := []sandbox.Rule{
		{Action: sandbox.Deny, Scope: sandbox.FileWrite},
	}
	cfg := sandbox.Configuration{
		Rules: rules,
	}

	instance, err := sandbox.New(context.Background(), &cfg)
	if err != nil {
		log.Fatal(err)
	}

	if err := instance.Run(context.Background(), command); err != nil {
		log.Fatal(err)
	}

	time.Sleep(60 * time.Second)
	instance.Clear()
}

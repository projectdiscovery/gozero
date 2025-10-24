package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/projectdiscovery/gozero/sandbox"
)

func main() {
	ctx := context.Background()

	// Check if Docker is available
	installed, err := sandbox.IsDockerInstalled(ctx)
	if err != nil {
		log.Fatalf("Error checking Docker installation: %v", err)
	}
	if !installed {
		log.Fatal("Docker is not installed")
	}

	enabled, err := sandbox.IsDockerEnabled(ctx)
	if err != nil {
		log.Fatalf("Error checking Docker status: %v", err)
	}
	if !enabled {
		log.Fatal("Docker daemon is not running")
	}

	// Create Docker sandbox configuration
	// Note: The image will be automatically pulled if it doesn't exist locally
	config := &sandbox.DockerConfiguration{
		Image:      "alpine:latest",
		WorkingDir: "/tmp",
		Environment: map[string]string{
			"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		},
		NetworkMode:     "bridge", // or "host", "none", etc.
		NetworkDisabled: false,    // Set to true to disable networking entirely
		User:            "root",
		Memory:          "128m", // Alpine is much lighter, can use less memory
		CPULimit:        "0.5",
		Timeout:         30 * time.Second,
		Remove:          true,
	}

	// Create Docker sandbox
	sandboxInstance, err := sandbox.NewDockerSandbox(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create Docker sandbox: %v", err)
	}
	defer sandboxInstance.Clear()

	// Test commands
	commands := []string{
		"echo 'Hello from Docker sandbox!'",
		"whoami",
		"pwd",
		"ls -la /",
		"uname -a",
	}

	for _, cmd := range commands {
		fmt.Printf("\n=== Running: %s ===\n", cmd)
		result, err := sandboxInstance.Run(ctx, cmd)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		fmt.Printf("Exit Code: %d\n", result.GetExitCode())
		fmt.Printf("Stdout: %s\n", result.Stdout.String())
		if result.Stderr.Len() > 0 {
			fmt.Printf("Stderr: %s\n", result.Stderr.String())
		}
	}

	fmt.Println("\n=== Docker sandbox test completed ===")
}

package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/projectdiscovery/gozero/sandbox"
	osutils "github.com/projectdiscovery/utils/os"
)

func main() {
	ctx := context.Background()

	if !osutils.IsLinux() {
		log.Printf("This example is only supported on Linux")
		return
	}

	// Create Docker sandbox configuration for shell execution
	config := &sandbox.DockerConfiguration{
		Image:      "alpine:latest",
		WorkingDir: "/tmp",
		Environment: map[string]string{
			"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		},
		NetworkMode:     "bridge",
		NetworkDisabled: false,
		User:            "root",
		Memory:          "128m",
		CPULimit:        "0.5",
		Timeout:         30 * time.Second,
		Remove:          true,
	}

	// Create Docker sandbox
	sandboxInstance, err := sandbox.NewDockerSandbox(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create Docker sandbox: %v", err)
	}
	defer func() {
		err := sandboxInstance.Clear()
		if err != nil {
			log.Fatalf("Failed to clear Docker sandbox: %v", err)
		}
	}()

	// Test shell scripts using RunSource
	scripts := []struct {
		name   string
		script string
	}{
		{
			name: "Simple Hello World",
			script: `#!/bin/sh
echo "Hello from shell script!"
echo "Current user: $(whoami)"
echo "Current directory: $(pwd)"
echo "System info: $(uname -a)"
`,
		},
		{
			name: "File Operations",
			script: `#!/bin/sh
echo "Creating test files..."
echo "File 1 content" > /tmp/test1.txt
echo "File 2 content" > /tmp/test2.txt
echo "Files created:"
ls -la /tmp/test*.txt
echo "File contents:"
cat /tmp/test1.txt
cat /tmp/test2.txt
`,
		},
		{
			name: "System Information",
			script: `#!/bin/sh
echo "=== System Information ==="
echo "Hostname: $(hostname)"
echo "User: $(whoami)"
echo "UID: $(id -u)"
echo "GID: $(id -g)"
echo "Groups: $(id -G)"
echo "Home: $HOME"
echo "Shell: $SHELL"
echo "PATH: $PATH"
echo ""
echo "=== Memory Information ==="
cat /proc/meminfo | head -5
echo ""
echo "=== CPU Information ==="
cat /proc/cpuinfo | head -10
`,
		},
		{
			name: "Network Test",
			script: `#!/bin/sh
echo "=== Network Configuration ==="
echo "Hostname: $(hostname)"
echo "IP addresses:"
ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo "Network tools not available"
echo ""
echo "=== DNS Resolution Test ==="
nslookup google.com 2>/dev/null || echo "DNS resolution not available"
`,
		},
	}

	for _, test := range scripts {
		fmt.Printf("\n=== Running: %s ===\n", test.name)
		result, err := sandboxInstance.RunSource(ctx, test.script)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		fmt.Printf("Exit Code: %d\n", result.GetExitCode())
		fmt.Printf("Stdout:\n%s\n", result.Stdout.String())
		if result.Stderr.Len() > 0 {
			fmt.Printf("Stderr:\n%s\n", result.Stderr.String())
		}
		fmt.Println("---")
	}

	fmt.Println("\n=== Shell source execution test completed ===")
}

//go:build linux

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/projectdiscovery/gozero/sandbox"
	osutils "github.com/projectdiscovery/utils/os"
)

func main() {
	ctx := context.Background()

	if !osutils.IsLinux() {
		log.Printf("This example is only supported on Linux")
		return
	}

	fmt.Println("=== Bubblewrap Sandbox Example ===")
	fmt.Println()

	// Create bubblewrap configuration with static settings
	config := &sandbox.BubblewrapConfiguration{
		TempDir:        filepath.Join(os.TempDir(), "gozero-bubblewrap"),
		UnsharePID:     true,
		UnshareIPC:     true,
		UnshareNetwork: true,
		UnshareUTS:     true,
		UnshareUser:    true,
		NewSession:     true,
		HostFilesystem: true,
		Environment: map[string]string{
			"PATH": "/usr/bin:/bin",
		},
	}

	// Create bubblewrap sandbox
	bwrap, err := sandbox.NewBubblewrapSandbox(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create bubblewrap sandbox: %v", err)
	}
	defer bwrap.Clear()

	fmt.Println("1. Running a simple command in the sandbox...")
	result, err := bwrap.Run(ctx, "echo 'Hello from bubblewrap sandbox!'")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Exit Code: %d\n", result.GetExitCode())
		fmt.Printf("Output: %s\n", result.Stdout.String())
		if result.Stderr.Len() > 0 {
			fmt.Printf("Errors: %s\n", result.Stderr.String())
		}
	}
	fmt.Println("---")

	fmt.Println("2. Running ls command in the sandbox...")
	result, err = bwrap.Run(ctx, "ls /")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Exit Code: %d\n", result.GetExitCode())
		fmt.Printf("Output: %s\n", result.Stdout.String())
		if result.Stderr.Len() > 0 {
			fmt.Printf("Errors: %s\n", result.Stderr.String())
		}
	}
	fmt.Println("---")

	fmt.Println("3. Running env command to see sandbox environment...")
	result, err = bwrap.Run(ctx, "env")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Exit Code: %d\n", result.GetExitCode())
		fmt.Printf("Output: %s\n", result.Stdout.String())
		if result.Stderr.Len() > 0 {
			fmt.Printf("Errors: %s\n", result.Stderr.String())
		}
	}
	fmt.Println("---")

	fmt.Println("4. Running Python source code in the sandbox...")
	pyCode := `print("Hello from Python in bubblewrap!")
print("Python is working in the sandbox!")
import sys
print(f"Python version: {sys.version}")
`
	result, err = bwrap.RunSource(ctx, pyCode)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Exit Code: %d\n", result.GetExitCode())
		fmt.Printf("Output: %s\n", result.Stdout.String())
		if result.Stderr.Len() > 0 {
			fmt.Printf("Errors: %s\n", result.Stderr.String())
		}
	}
	fmt.Println("---")

	fmt.Println("5. Using ExecuteWithOptions with per-command configuration...")
	options := &sandbox.BubblewrapCommandOptions{
		Command: "bash",
		Args:    []string{"-c", "echo 'Hello from per-command options!' && ls /src"},
		CommandBinds: []sandbox.BindMount{
			{HostPath: "/usr/bin", SandboxPath: "/usr/bin"},
		},
		WorkingDir: "/src",
	}
	result, err = bwrap.ExecuteWithOptions(ctx, options)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Exit Code: %d\n", result.GetExitCode())
		fmt.Printf("Output: %s\n", result.Stdout.String())
		if result.Stderr.Len() > 0 {
			fmt.Printf("Errors: %s\n", result.Stderr.String())
		}
	}
	fmt.Println("---")

	fmt.Println("=== Bubblewrap sandbox test completed ===")
}

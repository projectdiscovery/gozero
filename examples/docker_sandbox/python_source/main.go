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

	// Create Docker sandbox configuration for Python execution
	// Using Alpine Python image for minimal size
	config := &sandbox.DockerConfiguration{
		Image:      "python:3.11-alpine", // Alpine-based Python image
		WorkingDir: "/tmp",
		Environment: map[string]string{
			"PATH":       "/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"PYTHONPATH": "/tmp",
		},
		NetworkMode:     "bridge",
		NetworkDisabled: false,
		User:            "root",
		Memory:          "256m", // Python needs a bit more memory
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

	// Test Python scripts using RunSource
	scripts := []struct {
		name   string
		script string
	}{
		{
			name: "Simple Hello World",
			script: `#!/usr/bin/env python3
import sys
import os
import platform

print("Hello from Python script!")
print(f"Python version: {sys.version}")
print(f"Platform: {platform.platform()}")
print(f"Current user: {os.getenv('USER', 'unknown')}")
print(f"Current directory: {os.getcwd()}")
print(f"Python executable: {sys.executable}")
`,
		},
		{
			name: "Math and Data Processing",
			script: `#!/usr/bin/env python3
import math
import random
import json
from datetime import datetime

print("=== Math Operations ===")
print(f"Pi: {math.pi}")
print(f"E: {math.e}")
print(f"Square root of 16: {math.sqrt(16)}")
print(f"2^10: {2**10}")

print("\n=== Random Numbers ===")
random.seed(42)  # For reproducible results
for i in range(5):
    print(f"Random number {i+1}: {random.randint(1, 100)}")

print("\n=== JSON Processing ===")
data = {
    "name": "Python Script",
    "timestamp": datetime.now().isoformat(),
    "values": [1, 2, 3, 4, 5],
    "nested": {"key": "value"}
}
json_str = json.dumps(data, indent=2)
print("JSON data:")
print(json_str)

print("\n=== List Comprehensions ===")
squares = [x**2 for x in range(1, 6)]
print(f"Squares of 1-5: {squares}")

even_squares = [x**2 for x in range(1, 11) if x % 2 == 0]
print(f"Even squares of 1-10: {even_squares}")
`,
		},
		{
			name: "File Operations",
			script: `#!/usr/bin/env python3
import os
import tempfile
import json

print("=== File Operations ===")

# Create some test files
test_data = {
    "numbers": [1, 2, 3, 4, 5],
    "text": "Hello from Python!",
    "nested": {"a": 1, "b": 2}
}

# Write JSON file
with open('/tmp/test.json', 'w') as f:
    json.dump(test_data, f, indent=2)

# Write text file
with open('/tmp/test.txt', 'w') as f:
    f.write("This is a test file created by Python\n")
    f.write("Line 2\n")
    f.write("Line 3\n")

# Read and display files
print("Files created:")
for filename in ['/tmp/test.json', '/tmp/test.txt']:
    if os.path.exists(filename):
        print(f"\\n--- {filename} ---")
        with open(filename, 'r') as f:
            print(f.read())

# List directory contents
print("\\nDirectory contents:")
for item in os.listdir('/tmp'):
    if item.startswith('test'):
        full_path = os.path.join('/tmp', item)
        size = os.path.getsize(full_path)
        print(f"  {item} ({size} bytes)")
`,
		},
		{
			name: "System Information",
			script: `#!/usr/bin/env python3
import sys
import os
import platform
import subprocess
import json

print("=== Python Environment ===")
print(f"Python version: {sys.version}")
print(f"Python executable: {sys.executable}")
print(f"Platform: {platform.platform()}")
print(f"Architecture: {platform.architecture()}")
print(f"Machine: {platform.machine()}")
print(f"Processor: {platform.processor()}")

print("\\n=== System Information ===")
print(f"Current working directory: {os.getcwd()}")
print(f"User: {os.getenv('USER', 'unknown')}")
print(f"Home directory: {os.getenv('HOME', 'unknown')}")
print(f"PATH: {os.getenv('PATH', 'unknown')}")

print("\\n=== Environment Variables ===")
env_vars = ['PATH', 'HOME', 'USER', 'SHELL', 'PYTHONPATH']
for var in env_vars:
    value = os.getenv(var, 'Not set')
    print(f"{var}: {value}")

print("\\n=== Process Information ===")
print(f"Process ID: {os.getpid()}")
print(f"Parent Process ID: {os.getppid()}")

# Try to get system info (may not work in all containers)
try:
    result = subprocess.run(['uname', '-a'], capture_output=True, text=True, timeout=5)
    if result.returncode == 0:
        print(f"\\nSystem info: {result.stdout.strip()}")
except Exception as e:
    print(f"\\nCould not get system info: {e}")

print("\\n=== Memory Usage ===")
try:
    import psutil
    memory = psutil.virtual_memory()
    print(f"Total memory: {memory.total / (1024**3):.2f} GB")
    print(f"Available memory: {memory.available / (1024**3):.2f} GB")
except ImportError:
    print("psutil not available for memory info")
except Exception as e:
    print(f"Could not get memory info: {e}")
`,
		},
		{
			name: "Error Handling and Exception Testing",
			script: `#!/usr/bin/env python3
import sys
import traceback

print("=== Error Handling Examples ===")

# Test different types of errors
def test_division_by_zero():
    try:
        result = 10 / 0
        return result
    except ZeroDivisionError as e:
        return f"Caught ZeroDivisionError: {e}"

def test_file_not_found():
    try:
        with open('/nonexistent/file.txt', 'r') as f:
            return f.read()
    except FileNotFoundError as e:
        return f"Caught FileNotFoundError: {e}"

def test_value_error():
    try:
        result = int("not_a_number")
        return result
    except ValueError as e:
        return f"Caught ValueError: {e}"

def test_key_error():
    try:
        my_dict = {"a": 1, "b": 2}
        return my_dict["c"]
    except KeyError as e:
        return f"Caught KeyError: {e}"

# Run error tests
print("1. Division by zero:")
print(test_division_by_zero())

print("\\n2. File not found:")
print(test_file_not_found())

print("\\n3. Value error:")
print(test_value_error())

print("\\n4. Key error:")
print(test_key_error())

print("\\n=== Exception with traceback ===")
try:
    # This will raise an exception
    x = 1 / 0
except Exception as e:
    print(f"Exception occurred: {e}")
    print("Traceback:")
    traceback.print_exc()

print("\\n=== Custom Exception ===")
class CustomError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

try:
    raise CustomError("This is a custom error!")
except CustomError as e:
    print(f"Caught custom error: {e}")
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

	fmt.Println("\n=== Python source execution test completed ===")
}

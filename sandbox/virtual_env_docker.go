//nolint:exhaustruct,exhaustruct_v5 // the Docker API option and config structs use zero values for unset fields
package sandbox

import (
	"context"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/projectdiscovery/gozero/types"
)

// DockerConfiguration represents the configuration for Docker sandbox
type DockerConfiguration struct {
	Image           string            // Docker image to use (e.g., "ubuntu:20.04", "alpine:latest")
	WorkingDir      string            // Working directory inside container
	Environment     map[string]string // Environment variables
	NetworkMode     string            // Network mode (bridge, host, etc.)
	NetworkDisabled bool              // Disable networking entirely
	User            string            // User to run as inside container
	Memory          string            // Memory limit (e.g., "512m", "1g")
	CPULimit        string            // CPU limit (e.g., "0.5", "1.0")
	Timeout         time.Duration     // Command timeout
	Remove          bool              // Whether to remove container after execution
}

// SandboxDocker implements the Sandbox interface using Docker containers
type SandboxDocker struct {
	config       *DockerConfiguration
	dockerClient *client.Client
}

// NewDockerSandbox creates a new Docker-based sandbox
func NewDockerSandbox(ctx context.Context, config *DockerConfiguration) (*SandboxDocker, error) {
	// Check if Docker is available
	if ok, err := isDockerInstalled(ctx); err != nil || !ok {
		return nil, fmt.Errorf("docker not available: %w", err)
	}

	// Create Docker client
	dockerClient, err := client.New(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	// Test Docker connection
	_, err = dockerClient.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true})
	if err != nil {
		_ = dockerClient.Close()
		return nil, fmt.Errorf("failed to connect to docker daemon: %w", err)
	}

	// Validate required configuration
	if config.Image == "" {
		_ = dockerClient.Close()
		return nil, fmt.Errorf("docker image must be specified")
	}
	if config.WorkingDir == "" {
		_ = dockerClient.Close()
		return nil, fmt.Errorf("working directory must be specified")
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.Remove {
		config.Remove = true // Default to removing containers
	}

	return &SandboxDocker{
		config:       config,
		dockerClient: dockerClient,
	}, nil
}

// DockerSourceOptions holds the per-run inputs of RunSourceWithOptions.
type DockerSourceOptions struct {
	// Interpreter runs the source file. If it is empty or the source starts
	// with a shebang, the source file runs directly.
	Interpreter string
	// InterpreterArgs are passed to Interpreter before the source path.
	InterpreterArgs []string
	// Args are passed to the source after its path.
	Args []string
	// Stdin is copied to the standard input of the source until EOF or
	// until the container exits. If nil, the container has no standard
	// input. A read from Stdin can still be pending when the run returns.
	Stdin io.Reader
}

// Run executes a command in the Docker container (synchronous execution)
func (s *SandboxDocker) Run(ctx context.Context, cmd string) (*types.Result, error) {
	// Parse command into parts
	cmdParts := strings.Fields(cmd)

	return s.runCommand(ctx, cmdParts, cmd, nil)
}

// RunScript executes a script in the Docker container
func (s *SandboxDocker) RunScript(ctx context.Context, source string, interpreter string) (*types.Result, error) {
	return s.RunSource(ctx, source, interpreter)
}

// RunSource writes source code to a temporary file inside the container and executes it.
// The interpreter can include arguments, such as "python3 -u".
func (s *SandboxDocker) RunSource(ctx context.Context, source string, interpreter string) (*types.Result, error) {
	var opts DockerSourceOptions
	if fields := strings.Fields(interpreter); len(fields) > 0 {
		opts.Interpreter, opts.InterpreterArgs = fields[0], fields[1:]
	}

	return s.RunSourceWithOptions(ctx, source, opts)
}

// RunSourceWithOptions writes source code to a temporary file inside the
// container and executes it with the arguments and stdin in opts.
func (s *SandboxDocker) RunSourceWithOptions(
	ctx context.Context, source string, opts DockerSourceOptions,
) (*types.Result, error) {
	// Generate a temporary filename
	tmpFileName := fmt.Sprintf("/tmp/gozero_script_%d", time.Now().UnixNano())

	// A source with a shebang, or without an interpreter, runs directly
	var execArgs []string
	if opts.Interpreter != "" && !strings.HasPrefix(source, "#!") {
		execArgs = append(execArgs, opts.Interpreter)
		execArgs = append(execArgs, opts.InterpreterArgs...)
	}

	execArgs = append(execArgs, tmpFileName)
	execArgs = append(execArgs, opts.Args...)

	// Create a script that writes the source content and then executes its
	// positional parameters, so the shell never parses the arguments
	scriptContent := fmt.Sprintf(`cat > %s << 'EOF'
%s
EOF
chmod +x %s
exec "$@"
`, tmpFileName, source, tmpFileName)

	log.Println(tmpFileName)
	log.Println(scriptContent)

	// "sh" is the script's $0 and execArgs are its "$@"
	cmdParts := append([]string{"/bin/sh", "-c", scriptContent, "sh"}, execArgs...)

	return s.runCommand(ctx, cmdParts, "exec "+tmpFileName, opts.Stdin)
}

// Start is not implemented for Docker sandbox as it's stateless
func (s *SandboxDocker) Start() error {
	return ErrNotImplemented
}

// Wait is not implemented for Docker sandbox as it's stateless
func (s *SandboxDocker) Wait() error {
	return ErrNotImplemented
}

// Stop is not implemented for Docker sandbox as it's stateless
func (s *SandboxDocker) Stop() error {
	return ErrNotImplemented
}

// Clear cleans up Docker resources (containers, images, etc.)
func (s *SandboxDocker) Clear() error {
	if s.dockerClient != nil {
		return s.dockerClient.Close()
	}
	return nil
}

// isDockerInstalled checks if Docker is installed and available by executing docker info
func isDockerInstalled(ctx context.Context) (bool, error) {
	cmd := exec.CommandContext(ctx, "docker", "info")
	err := cmd.Run()
	if err != nil {
		return false, err
	}
	return true, nil
}

// parseMemoryLimit parses memory limit string (e.g., "512m", "1g") to bytes
func parseMemoryLimit(memory string) int64 {
	if memory == "" {
		return 0
	}

	// Basic parsing - in production, use a proper library
	// This is a simplified implementation
	memory = strings.ToLower(strings.TrimSpace(memory))

	var multiplier int64 = 1
	if strings.HasSuffix(memory, "g") {
		multiplier = 1024 * 1024 * 1024
		memory = strings.TrimSuffix(memory, "g")
	} else if strings.HasSuffix(memory, "m") {
		multiplier = 1024 * 1024
		memory = strings.TrimSuffix(memory, "m")
	} else if strings.HasSuffix(memory, "k") {
		multiplier = 1024
		memory = strings.TrimSuffix(memory, "k")
	}

	// Parse the numeric part
	var value int64
	_, _ = fmt.Sscanf(memory, "%d", &value)
	return value * multiplier
}

// pullImageIfNeeded pulls the Docker image if it doesn't exist locally
func (s *SandboxDocker) pullImageIfNeeded(ctx context.Context, imageName string) error {
	// Check if image exists locally
	_, err := s.dockerClient.ImageInspect(ctx, imageName)
	if err == nil {
		// Image exists locally, no need to pull
		return nil
	}

	// Image doesn't exist, pull it
	reader, err := s.dockerClient.ImagePull(ctx, imageName, client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}
	defer func() {
		_ = reader.Close()
	}()

	// Read the pull progress to completion
	buf := make([]byte, 1024)
	for {
		_, readErr := reader.Read(buf)
		if readErr == nil {
			continue
		}
		// EOF is expected when pull completes successfully
		if readErr.Error() != "EOF" {
			return fmt.Errorf("failed to complete image pull: %w", readErr)
		}
		break
	}

	return nil
}

// runCommand executes a command in the Docker container with the given command parts.
func (s *SandboxDocker) runCommand(
	ctx context.Context, cmdParts []string, command string, stdin io.Reader,
) (*types.Result, error) {
	if len(cmdParts) == 0 {
		return nil, errEmptyCommand
	}

	// Create a new context with timeout
	runCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	// Pull image if it doesn't exist locally
	err := s.pullImageIfNeeded(runCtx, s.config.Image)
	if err != nil {
		return nil, fmt.Errorf("failed to pull image %s: %w", s.config.Image, err)
	}

	// Create container
	createResp, err := s.dockerClient.ContainerCreate(runCtx, client.ContainerCreateOptions{
		Config:     s.containerConfig(cmdParts, stdin != nil),
		HostConfig: s.hostConfig(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	containerID := createResp.ID

	// Always clean up the container, which isn't auto-removed so that its
	// logs can be read
	defer func() {
		_, _ = s.dockerClient.ContainerRemove(runCtx, containerID, client.ContainerRemoveOptions{Force: true})
	}()

	// Attach stdin before the start, as docker run -i does, so it is
	// connected for the whole run
	if stdin != nil {
		stopStdin, err := s.attachStdin(runCtx, containerID, stdin)
		if err != nil {
			return nil, err
		}

		defer stopStdin()
	}

	// Start container
	_, err = s.dockerClient.ContainerStart(runCtx, containerID, client.ContainerStartOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	// Wait for container to finish
	waitRes := s.dockerClient.ContainerWait(runCtx, containerID, client.ContainerWaitOptions{
		Condition: container.WaitConditionNotRunning,
	})

	select {
	case err := <-waitRes.Error:
		return nil, fmt.Errorf("container wait error: %w", err)
	case result := <-waitRes.Result:
		return s.collectResult(runCtx, containerID, command, result.StatusCode)
	}
}

// containerConfig returns the configuration of a container that runs cmd.
func (s *SandboxDocker) containerConfig(cmd []string, withStdin bool) *container.Config {
	// Prepare environment variables
	env := make([]string, 0, len(s.config.Environment))
	for key, value := range s.config.Environment {
		env = append(env, key+"="+value)
	}

	return &container.Config{
		Image:        s.config.Image,
		Cmd:          cmd,
		WorkingDir:   s.config.WorkingDir,
		Env:          env,
		User:         s.config.User,
		AttachStdout: true,
		AttachStderr: true,
		// Stdin stays open until the attached client closes it
		AttachStdin: withStdin,
		OpenStdin:   withStdin,
		StdinOnce:   withStdin,
	}
}

// hostConfig returns the host configuration of a container, with the network
// mode and memory limit of the sandbox.
func (s *SandboxDocker) hostConfig() *container.HostConfig {
	hostConfig := &container.HostConfig{
		AutoRemove: false, // Don't auto-remove so we can get logs
	}

	// Set network configuration
	if s.config.NetworkDisabled {
		hostConfig.NetworkMode = "none"
	} else if s.config.NetworkMode != "" {
		hostConfig.NetworkMode = container.NetworkMode(s.config.NetworkMode)
	}

	// Set resource limits if specified
	if s.config.Memory != "" {
		hostConfig.Memory = parseMemoryLimit(s.config.Memory)
	}

	return hostConfig
}

// attachStdin copies stdin to the standard input of a created container. The
// returned stop function closes the connection, which ends the copy at its
// next write; call it after the container exits. Like docker run -i, stop
// doesn't wait for a pending read from stdin, which may never return.
func (s *SandboxDocker) attachStdin(ctx context.Context, containerID string, stdin io.Reader) (func(), error) {
	attach, err := s.dockerClient.ContainerAttach(ctx, containerID, client.ContainerAttachOptions{
		Stream: true,
		Stdin:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach container stdin: %w", err)
	}

	go func() {
		_, _ = io.Copy(attach.Conn, stdin)
		// Closing the write side closes the container's stdin
		_ = attach.CloseWrite()
	}()

	return attach.Close, nil
}

// logBufferSize is the size of the buffer that collectResult reads container
// logs into.
const logBufferSize = 1024 * 1024 // 1MB

// collectResult reads the output of an exited container into a Result.
func (s *SandboxDocker) collectResult(
	ctx context.Context, containerID, command string, statusCode int64,
) (*types.Result, error) {
	// Get container logs
	logs, err := s.dockerClient.ContainerLogs(ctx, containerID, client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get container logs: %w", err)
	}

	defer func() {
		_ = logs.Close()
	}()

	// Read logs
	logData := make([]byte, logBufferSize)

	size, err := logs.Read(logData)
	if err != nil && err.Error() != "EOF" {
		return nil, fmt.Errorf("failed to read container logs: %w", err)
	}

	// Create result
	cmdResult := &types.Result{
		Command: command,
	}
	cmdResult.Stdout.Write(logData[:size])

	// Set exit code
	if statusCode != 0 {
		cmdResult.SetExitError(&exec.ExitError{})
	}

	return cmdResult, nil
}

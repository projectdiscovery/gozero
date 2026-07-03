package confine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
	"github.com/projectdiscovery/gozero/types"
)

// containerSourceDir is where the payload's source file is injected inside the
// container. It lives on the (read-only-at-runtime) rootfs; it only needs to be
// readable/executable at runtime, and it is written before the container starts.
const containerSourceDir = "/gozero-src"

// containerWorkDir is a writable tmpfs the payload runs in, so a read-only
// rootfs never blocks legitimate scratch writes.
const containerWorkDir = "/work"

// dockerConfiner runs each payload in a fresh, hardened, single-shot container.
type dockerConfiner struct {
	policy Policy
	cli    *client.Client
	image  string
}

// newDockerConfiner connects to the daemon and validates the image, failing
// closed (returning ErrConfinementUnavailable) when Docker is not usable — so a
// caller that asked for Docker confinement never runs unconfined.
func newDockerConfiner(p Policy) (*dockerConfiner, error) {
	cli, err := client.New(client.FromEnv)
	if err != nil {
		p.Logger.Debug("confine: docker unavailable", "reason", "client init failed", "error", err)
		return nil, ErrConfinementUnavailable
	}
	pingCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := cli.Ping(pingCtx, client.PingOptions{NegotiateAPIVersion: true}); err != nil {
		_ = cli.Close()
		p.Logger.Debug("confine: docker unavailable", "reason", "daemon ping failed", "error", err)
		return nil, ErrConfinementUnavailable
	}
	return &dockerConfiner{policy: p, cli: cli, image: p.DockerImage}, nil
}

func (c *dockerConfiner) Name() string { return "docker" }

func (c *dockerConfiner) Close() error {
	if c.cli != nil {
		return c.cli.Close()
	}
	return nil
}

func (c *dockerConfiner) Run(ctx context.Context, spec Spec) (*types.Result, error) {
	if len(spec.Command) == 0 {
		return nil, ErrNoCommand
	}

	ctx, cancel := withTimeout(ctx, c.policy.Timeout)
	defer cancel()

	if err := c.ensureImage(ctx); err != nil {
		return nil, err
	}

	scriptName := "script"
	if spec.ScriptPath != "" {
		scriptName = filepath.Base(spec.ScriptPath)
	}
	containerScript := path.Join(containerSourceDir, scriptName)

	// The host's absolute interpreter path is meaningless inside the image, so
	// reference it by base name (e.g. /usr/bin/python3 -> python3) and let the
	// container's PATH resolve it.
	interp := filepath.Base(spec.Command[0])
	cmd := remapScript(spec.Command, spec.ScriptPath, containerScript, interp, true)

	env := customEnv(spec.Env)
	env["HOME"] = containerWorkDir
	env["TMPDIR"] = "/tmp"

	// A non-root identity is only forced when the policy sets one explicitly
	// (RunAsUID >= 0). The default (-1) leaves the image's own user in place,
	// because forcing an arbitrary uid breaks images without a matching passwd
	// entry — the container is already hardened by cap-drop, no-new-privileges,
	// a read-only rootfs and no network.
	user := ""
	if c.policy.RunAsUID >= 0 {
		user = fmt.Sprintf("%d", c.policy.RunAsUID)
		if c.policy.RunAsGID >= 0 {
			user = fmt.Sprintf("%d:%d", c.policy.RunAsUID, c.policy.RunAsGID)
		}
	}

	wantStdin := spec.Stdin != nil
	cfg := dockerContainerConfig(c.image, cmd, containerWorkDir, envMapToSlice(env), user, wantStdin)
	hostCfg := dockerHostConfig(c.policy)

	// Expose the source through a private read-only bind mount, never as shell
	// text. CopyToContainer cannot reliably inject into a container whose rootfs
	// is configured read-only, and relaxing ReadonlyRootfs for injection weakens
	// the runtime posture. A bind of one temp dir keeps the rootfs read-only and
	// gives the payload access to only this generated source file.
	srcData := spec.ScriptData
	if srcData == nil {
		srcData = []byte{}
	}
	sourceDir, err := os.MkdirTemp("", "gozero-docker-src-*")
	if err != nil {
		return nil, fmt.Errorf("confine: create source dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(sourceDir) }()
	if err := os.WriteFile(filepath.Join(sourceDir, scriptName), srcData, 0o700); err != nil {
		return nil, fmt.Errorf("confine: write source: %w", err)
	}
	hostCfg.Mounts = append(hostCfg.Mounts, mount.Mount{
		Type:     mount.TypeBind,
		Source:   sourceDir,
		Target:   containerSourceDir,
		ReadOnly: true,
	})

	createResp, err := c.cli.ContainerCreate(ctx, client.ContainerCreateOptions{Config: cfg, HostConfig: hostCfg})
	if err != nil {
		return nil, fmt.Errorf("confine: create container: %w", err)
	}
	id := createResp.ID
	defer func() {
		rmCtx, rmCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer rmCancel()
		_, _ = c.cli.ContainerRemove(rmCtx, id, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
	}()

	// Attach stdin (only) before start so the payload can read it. stdout/stderr
	// are collected from the logs stream after exit, demultiplexed via stdcopy.
	var attach client.ContainerAttachResult
	if wantStdin {
		attach, err = c.cli.ContainerAttach(ctx, id, client.ContainerAttachOptions{Stream: true, Stdin: true})
		if err != nil {
			return nil, fmt.Errorf("confine: attach stdin: %w", err)
		}
		defer attach.Close()
	}

	// Register the wait BEFORE start using NextExit: WaitConditionNotRunning is
	// satisfied immediately by a freshly created (not-yet-started) container and
	// returns a bogus StatusCode 0, so it must not be used in the wait-then-start
	// ordering. NextExit resolves only when the container next exits.
	waitRes := c.cli.ContainerWait(ctx, id, client.ContainerWaitOptions{Condition: container.WaitConditionNextExit})

	if _, err := c.cli.ContainerStart(ctx, id, client.ContainerStartOptions{}); err != nil {
		return nil, fmt.Errorf("confine: start container: %w", err)
	}

	if wantStdin {
		go func() {
			_, _ = io.Copy(attach.Conn, spec.Stdin)
			if cw, ok := attach.Conn.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
		}()
	}

	var status int64
	select {
	case werr := <-waitRes.Error:
		if werr != nil {
			return nil, fmt.Errorf("confine: wait container: %w", werr)
		}
	case wr := <-waitRes.Result:
		status = wr.StatusCode
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	res := &types.Result{Command: strings.Join(cmd, " ")}
	if err := c.collectLogs(ctx, id, res, spec.Debug); err != nil {
		return res, err
	}
	res.SetExitCode(int(status))
	return res, nil
}

// collectLogs reads the container's multiplexed log stream and demultiplexes it
// into the result's stdout/stderr buffers via stdcopy, so no 8-byte frame
// headers leak into the output and nothing is truncated.
func (c *dockerConfiner) collectLogs(ctx context.Context, id string, res *types.Result, debug bool) error {
	logs, err := c.cli.ContainerLogs(ctx, id, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {
		return fmt.Errorf("confine: read container logs: %w", err)
	}
	defer func() { _ = logs.Close() }()

	var stdout, stderr io.Writer = &res.Stdout, &res.Stderr
	if debug {
		res.DebugData = &bytes.Buffer{}
		stdout = io.MultiWriter(&res.Stdout, res.DebugData)
		stderr = io.MultiWriter(&res.Stderr, res.DebugData)
	}
	if _, err := stdcopy.StdCopy(stdout, stderr, logs); err != nil && err != io.EOF {
		return fmt.Errorf("confine: demux container logs: %w", err)
	}
	return nil
}

// ensureImage pulls the image if it is not already present locally, bounded by
// the policy's pull timeout.
func (c *dockerConfiner) ensureImage(ctx context.Context) error {
	if _, err := c.cli.ImageInspect(ctx, c.image); err == nil {
		return nil
	}
	pullCtx, cancel := context.WithTimeout(ctx, c.policy.PullTimeout)
	defer cancel()

	c.policy.Logger.Info("confine: pulling docker image", "image", c.image)
	reader, err := c.cli.ImagePull(pullCtx, c.image, client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("confine: pull image %s: %w", c.image, err)
	}
	defer func() { _ = reader.Close() }()
	// Drain the pull progress to completion (pull is async; the stream must be
	// fully consumed for the image to finish downloading).
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return fmt.Errorf("confine: complete image pull %s: %w", c.image, err)
	}
	return nil
}

// dockerContainerConfig builds the portable container config. Stdin plumbing is
// only enabled when the caller supplies input; user is set only when non-empty.
func dockerContainerConfig(image string, cmd []string, workdir string, env []string, user string, wantStdin bool) *container.Config {
	cfg := &container.Config{
		Image:        image,
		Cmd:          cmd,
		WorkingDir:   workdir,
		Env:          env,
		User:         user,
		AttachStdout: true,
		AttachStderr: true,
	}
	if wantStdin {
		cfg.AttachStdin = true
		cfg.OpenStdin = true
		cfg.StdinOnce = true
	}
	return cfg
}

// dockerHostConfig translates the policy into a hardened, deny-by-default host
// config. This is the core of the Docker escape mitigation:
//
//   - NetworkMode "none": no network unless explicitly allowed (anti-exfil).
//   - CapDrop ALL: strip every Linux capability.
//   - no-new-privileges: setuid/setgid binaries can't raise privileges.
//   - ReadonlyRootfs + tmpfs work/tmp: the payload can't tamper with the image;
//     it only has ephemeral scratch space.
//   - private cgroup/ipc/uts namespaces: no sharing with host or other containers.
//   - pids/memory/cpu limits: contain fork bombs and resource exhaustion.
//   - Privileged is never set.
func dockerHostConfig(p Policy) *container.HostConfig {
	hc := &container.HostConfig{
		AutoRemove:     false, // we remove explicitly so we can still read logs
		ReadonlyRootfs: p.ReadonlyRootfs,
		CgroupnsMode:   container.CgroupnsModePrivate,
		IpcMode:        container.IPCModePrivate,
		Privileged:     false,
		Tmpfs: map[string]string{
			containerWorkDir: "rw,nosuid,nodev,size=64m",
			"/tmp":           "rw,nosuid,nodev,size=64m",
		},
	}

	if !p.AllowNetwork {
		hc.NetworkMode = "none"
	}
	if p.DropAllCapabilities {
		hc.CapDrop = []string{"ALL"}
	}
	if p.NoNewPrivileges {
		hc.SecurityOpt = append(hc.SecurityOpt, "no-new-privileges:true")
	}
	if p.PidsLimit > 0 {
		limit := p.PidsLimit
		hc.PidsLimit = &limit
	}
	if p.MemoryBytes > 0 {
		hc.Memory = p.MemoryBytes
	}
	if p.NanoCPUs > 0 {
		hc.NanoCPUs = p.NanoCPUs
	}
	return hc
}

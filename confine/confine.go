// Package confine is gozero's code-execution confinement layer.
//
// It exists to eliminate the "sandbox escape" error class: when a caller asks
// for confinement, code MUST run inside an OS-enforced boundary or not run at
// all. There is deliberately no silent fallback to a bare host exec — an
// unavailable or unhealthy confiner is a hard error (fail closed). This is the
// single property that turns "we tried to sandbox" into "it is impossible to
// execute unconfined once confinement is requested".
//
// Design (state of the art, deny-by-default):
//
//   - One seam. Every backend implements the same Confiner and every execution
//     path goes through Run, so there is no second, unconfined code path to
//     forget about.
//   - Deny by default. No network, all Linux capabilities dropped,
//     no-new-privileges, read-only root filesystem, private namespaces, a
//     minimal scrubbed environment, non-root identity and CPU/memory/pids
//     limits are all ON unless the policy explicitly relaxes them.
//   - Least authority for the payload. Source is delivered as bytes (a bind or a
//     tar copy), never interpolated into a shell — so there is no heredoc/quote
//     breakout and the declared interpreter is the only thing that runs it.
//   - Ephemeral. Each execution gets a fresh writable workspace that is torn
//     down afterwards; the read-only root and container are disposable.
//
// Backends:
//
//   - bubblewrap (Linux): transparent argv wrapper using user/mount/net/pid/…
//     namespaces + capability drop; a read-only view of the host root with a
//     single writable workspace bind.
//   - Seatbelt (macOS): sandbox-exec with an SBPL profile that denies writes
//     outside the workspace/temp (and, optionally, all network).
//   - Docker (any OS with a daemon): a hardened, single-shot container
//     (--network none, --cap-drop ALL, no-new-privileges, --read-only, pids/cpu/
//     memory limits, non-root) with the source injected via the archive API.
package confine

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/projectdiscovery/gozero/types"
)

// Backend selects which confinement mechanism to use.
type Backend string

const (
	// BackendAuto picks the best native confiner for the current OS
	// (bubblewrap on Linux, Seatbelt on macOS). It fails closed when none is
	// available.
	BackendAuto Backend = "auto"
	// BackendBubblewrap forces the Linux bubblewrap confiner.
	BackendBubblewrap Backend = "bubblewrap"
	// BackendSeatbelt forces the macOS Seatbelt confiner.
	BackendSeatbelt Backend = "seatbelt"
	// BackendDocker forces the hardened Docker confiner.
	BackendDocker Backend = "docker"
	// BackendHost is an explicit, deliberate opt-out: code runs on the host with
	// NO confinement. It must be chosen on purpose; it is never selected
	// implicitly and never used as a fallback.
	BackendHost Backend = "host"
)

// Sentinel errors. Callers should treat ErrConfinementUnavailable as fatal:
// the whole point of this package is that a requested-but-unavailable confiner
// never degrades into an unconfined run.
var (
	// ErrConfinementUnavailable is returned when the requested backend is not
	// present/usable on this host. Fail closed: do not execute.
	ErrConfinementUnavailable = errors.New("confine: requested confinement backend is not available on this host")
	// ErrUnsupportedBackend is returned for an unknown Backend value.
	ErrUnsupportedBackend = errors.New("confine: unsupported backend")
	// ErrNoCommand is returned when a Spec carries no command to execute.
	ErrNoCommand = errors.New("confine: spec has no command")
)

// Policy is the security posture applied to every execution a Confiner runs.
// The zero value is not meant to be used directly; call DefaultPolicy and tune
// from there, or rely on New to fill in safe defaults for unset fields.
type Policy struct {
	// Backend selects the confinement mechanism. Empty means BackendAuto.
	Backend Backend

	// AllowNetwork, when false (default), denies the payload all network egress
	// (empty net namespace / --network none / deny network*). Only loopback,
	// if anything, remains.
	AllowNetwork bool

	// Workspace is the writable root granted to the payload. When empty, an
	// ephemeral per-execution directory is created and removed afterwards.
	Workspace string
	// Tmp is an additional writable temp dir. Defaults to os.TempDir().
	Tmp string

	// DropAllCapabilities drops every Linux capability (docker/bwrap). Default true.
	DropAllCapabilities bool
	// NoNewPrivileges sets no_new_privs so setuid/setgid bits can't raise
	// privileges (docker). Default true.
	NoNewPrivileges bool
	// ReadonlyRootfs makes the root filesystem read-only (docker) / read-only
	// bind (bwrap). Default true.
	ReadonlyRootfs bool

	// PidsLimit caps the number of processes (docker). Default 128. <=0 disables.
	PidsLimit int64
	// MemoryBytes caps memory (docker). Default 512MiB. <=0 disables.
	MemoryBytes int64
	// NanoCPUs caps CPU in units of 1e-9 CPUs (docker). Default 1e9 (1 CPU).
	// <=0 disables.
	NanoCPUs int64

	// RunAsUID / RunAsGID set the identity the payload runs as. Negative means
	// "use the current process uid/gid" on unix (so workspace files stay owned
	// by the caller) and "image/OS default" where uid/gid are not meaningful.
	RunAsUID int
	RunAsGID int

	// AllowedEnv is the whitelist of host environment variables passed through
	// to the payload. Everything else in the host environment is scrubbed.
	AllowedEnv []string

	// DockerImage is the image used by the Docker backend.
	DockerImage string
	// PullTimeout bounds a docker image pull. Default 5m.
	PullTimeout time.Duration

	// Timeout bounds a single execution. 0 means "inherit the ctx deadline only".
	Timeout time.Duration

	// Logger receives diagnostic events. Defaults to slog.Default().
	Logger *slog.Logger
}

// defaultAllowedEnv is the minimal set of host environment variables passed
// through to a typical interpreter. Intentionally short: secrets live in the
// ambient environment and must not leak into untrusted code. PATH, HOME and
// TMPDIR are deliberately excluded — childEnv owns them (PATH from the host,
// HOME/TMPDIR pointed at the writable workspace) so host values can't override
// the sandbox's own locations.
var defaultAllowedEnv = []string{"LANG", "LC_ALL", "TERM", "TZ"}

const (
	defaultPidsLimit   = int64(128)
	defaultMemoryBytes = int64(512) * 1024 * 1024
	defaultNanoCPUs    = int64(1_000_000_000) // 1.0 CPU
	defaultPullTimeout = 5 * time.Minute
	// defaultDockerImage is a small, widely-available base. Callers running
	// non-shell interpreters should override it with an image that ships them.
	defaultDockerImage = "alpine:latest"
	// defaultPATH is the fallback search path when the host PATH is empty.
	defaultPATH = "/usr/local/bin:/usr/bin:/bin"
)

// DefaultPolicy returns a hardened, deny-by-default policy: no network, all
// capabilities dropped, no-new-privileges, read-only rootfs, private
// namespaces, resource limits, non-root, minimal environment.
func DefaultPolicy() Policy {
	return Policy{
		Backend:             BackendAuto,
		AllowNetwork:        false,
		DropAllCapabilities: true,
		NoNewPrivileges:     true,
		ReadonlyRootfs:      true,
		PidsLimit:           defaultPidsLimit,
		MemoryBytes:         defaultMemoryBytes,
		NanoCPUs:            defaultNanoCPUs,
		RunAsUID:            -1,
		RunAsGID:            -1,
		AllowedEnv:          append([]string(nil), defaultAllowedEnv...),
		DockerImage:         defaultDockerImage,
		PullTimeout:         defaultPullTimeout,
	}
}

// normalized returns a copy of p with unset fields filled from DefaultPolicy,
// so callers can pass a sparse Policy (e.g. only Backend + AllowNetwork) and
// still get the hardened defaults for everything they didn't set.
func (p Policy) normalized() Policy {
	d := DefaultPolicy()
	if p.Backend == "" {
		p.Backend = d.Backend
	}
	if p.Tmp == "" {
		p.Tmp = os.TempDir()
	}
	if p.PidsLimit == 0 {
		p.PidsLimit = d.PidsLimit
	}
	if p.MemoryBytes == 0 {
		p.MemoryBytes = d.MemoryBytes
	}
	if p.NanoCPUs == 0 {
		p.NanoCPUs = d.NanoCPUs
	}
	if p.RunAsUID == 0 && p.RunAsGID == 0 {
		// Treat the zero value as "unset" and default to current identity, so a
		// sparse policy never accidentally forces root (uid 0).
		p.RunAsUID, p.RunAsGID = -1, -1
	}
	if len(p.AllowedEnv) == 0 {
		p.AllowedEnv = append([]string(nil), defaultAllowedEnv...)
	}
	if p.DockerImage == "" {
		p.DockerImage = d.DockerImage
	}
	if p.PullTimeout == 0 {
		p.PullTimeout = d.PullTimeout
	}
	if p.Logger == nil {
		p.Logger = slog.Default()
	}
	return p
}

// Spec describes a single confined execution. Command is the full argv with the
// interpreter at index 0; ScriptPath/ScriptData identify the source file so
// backends can make it reachable inside the sandbox (a read-only bind for
// native confiners, an archive copy for Docker) instead of pasting it into a
// shell.
type Spec struct {
	// Command is the full argv: [interpreter, scriptPath, userArgs...].
	Command []string
	// ScriptPath is the host path of the source file that appears in Command.
	// Backends locate this element in Command to remap it into the sandbox.
	ScriptPath string
	// ScriptData is the source content, used by backends (Docker) that copy the
	// file in rather than binding the host path.
	ScriptData []byte
	// Env is the caller-supplied environment (e.g. template variables). It is
	// merged on top of the policy's environment allow-list and validated.
	Env map[string]string
	// Stdin is streamed to the payload's standard input.
	Stdin io.Reader
	// Workdir overrides the writable working directory. When empty the
	// confiner's ephemeral workspace is used.
	Workdir string
	// Debug mirrors gozero's debug mode: stdout+stderr are also captured into
	// Result.DebugData.
	Debug bool
}

// Confiner runs a Spec inside an OS-enforced boundary. Implementations must
// fail closed: if the boundary cannot be established, Run returns an error and
// never executes the payload on the bare host.
type Confiner interface {
	// Name identifies the confiner for logs ("bubblewrap", "seatbelt", "docker").
	Name() string
	// Run executes spec under confinement and returns its result.
	Run(ctx context.Context, spec Spec) (*types.Result, error)
	// Close releases any long-lived resources the confiner owns.
	Close() error
}

// New builds the Confiner for the given policy, failing closed. A nil policy
// means DefaultPolicy. For BackendAuto/native and BackendDocker, an
// unavailable mechanism returns ErrConfinementUnavailable rather than a
// permissive fallback — callers MUST treat that as "do not execute".
func New(policy *Policy) (Confiner, error) {
	if policy == nil {
		d := DefaultPolicy()
		policy = &d
	}
	// normalized() fills unset fields (including Logger) so the backend probes
	// below can rely on them; skipping it caused a nil-logger panic on the
	// nil-policy path.
	p := policy.normalized()

	switch p.Backend {
	case BackendHost:
		return hostConfiner{}, nil
	case BackendDocker:
		c, err := newDockerConfiner(p)
		if err != nil {
			return nil, err
		}
		return c, nil
	case BackendAuto, BackendBubblewrap, BackendSeatbelt:
		c := newNativeConfiner(p)
		if c == nil {
			return nil, ErrConfinementUnavailable
		}
		// When a specific native backend was requested, enforce that we got it.
		if p.Backend == BackendBubblewrap && c.Name() != "bubblewrap" {
			return nil, ErrConfinementUnavailable
		}
		if p.Backend == BackendSeatbelt && c.Name() != "seatbelt" {
			return nil, ErrConfinementUnavailable
		}
		return c, nil
	default:
		return nil, ErrUnsupportedBackend
	}
}

// Compile-time guarantees that every backend satisfies the single Confiner
// seam (the per-OS native confiners assert themselves in their tagged files).
var (
	_ Confiner = hostConfiner{}
	_ Confiner = (*dockerConfiner)(nil)
)

// hostConfiner is the explicit, deliberate no-confinement backend. It is only
// ever returned for BackendHost and never selected implicitly. It exists so the
// unconfined path is an auditable, named choice rather than a silent fallback.
type hostConfiner struct{}

func (hostConfiner) Name() string { return "host" }
func (hostConfiner) Close() error { return nil }

func (hostConfiner) Run(ctx context.Context, spec Spec) (*types.Result, error) {
	if len(spec.Command) == 0 {
		return nil, ErrNoCommand
	}
	env := childEnv(DefaultPolicy(), spec.Workdir, spec.Env)
	return runHost(ctx, spec.Command, envMapToSlice(env), spec.Stdin, spec.Workdir, spec.Debug)
}

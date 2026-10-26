# gozero

gozero: the wannabe zero dependency [language-here] runtime for Go developers

## Isolation

Confinement is provided by the `confine` package. It is deny-by-default (no
network, dropped capabilities, no-new-privileges, read-only root filesystem,
hidden home directory, private namespaces, cpu/memory/pids limits, non-root
user, minimal environment) and fail
closed: when confinement is requested but the backend is unavailable, execution
is refused instead of falling back to the host.

Backends:

- Linux: bubblewrap (`bwrap`).
- macOS: Seatbelt (`sandbox-exec`).
- Any OS with a Docker daemon: a hardened, single-shot container.

Source is passed to the interpreter as bytes, never interpolated into a shell.

## Usage

Confinement is off by default. Enable it per executor:

```go
opts := &gozero.Options{Engines: []string{"python3"}, Sandbox: true}
g, err := gozero.New(opts) // fails closed if no backend is available
```

Tune the posture with `Options.Confinement` (a `*confine.Policy`), or pick a
backend per call with `Gozero.EvalWithVirtualEnv`.

Every security switch in `confine.Policy` is an opt-out whose zero value is the hardened setting, so a sparse policy such as `&confine.Policy{Backend: confine.BackendDocker}` is fully hardened. The opt-outs are `AllowNetwork`, `AllowCapabilities`, `AllowNewPrivileges` and `WritableRootfs`.

### Home directory

The native backends hide `$HOME` from the payload. Seatbelt denies reads under it, and bubblewrap mounts an empty tmpfs over it. The payload cannot read `~/.ssh`, shell history or credentials. The workspace and the script directory stay reachable.

The native backends also hide the other users' homes and root's home (`/home` and `/root` on Linux, `/Users` and `/var/root` on macOS). On Linux they hide `/run` too: it holds daemon sockets such as the Docker socket, and an unshared network namespace does not block unix sockets. On macOS, the network deny blocks unix sockets.

Each native backend runs a probe once before use. If bubblewrap cannot create its namespaces (for example in an unprivileged container, or under Landlock, which forbids mounts), or if `sandbox-exec` cannot apply a profile, `New` returns `ErrConfinementUnavailable`.

If the interpreter lives under `$HOME` (pyenv, nvm, a Homebrew prefix in the home directory), list it in `ReadOnlyPaths`. Each entry is exposed read-only. A leading `~` is expanded. Paths outside `$HOME` are already readable and need no entry.

```go
policy := confine.DefaultPolicy()
policy.ReadOnlyPaths = []string{"~/.pyenv"}
opts := &gozero.Options{Engines: []string{"python3"}, Sandbox: true, Confinement: &policy}
```

### Docker user

The Docker backend runs the payload as `65534:65534` (nobody), not as the image user, which is root for most base images. `RunAsUID`/`RunAsGID` select another uid/gid, and `DockerUser` overrides the user verbatim (for example `"1000:1000"`).

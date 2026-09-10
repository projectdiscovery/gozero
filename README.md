# gozero

gozero: the wannabe zero dependency [language-here] runtime for Go developers

## Isolation

Confinement is provided by the `confine` package. It is deny-by-default (no
network, dropped capabilities, no-new-privileges, read-only root filesystem,
private namespaces, cpu/memory/pids limits, minimal environment) and fail
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

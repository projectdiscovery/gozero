package gozero

import "github.com/projectdiscovery/gozero/confine"

type Options struct {
	Engines            []string
	Args               []string
	engine             string
	PreferStartProcess bool

	// Sandbox requests confined execution. When true (or when Confinement is
	// set), Eval runs the payload through an OS-enforced boundary and FAILS
	// CLOSED: if no confinement backend is available, New returns an error and
	// nothing is ever executed on the bare host. Leaving it false preserves the
	// legacy, unconfined behaviour.
	Sandbox bool
	// Confinement is the confinement policy applied when Sandbox is on (or when
	// this is non-nil). Nil means confine.DefaultPolicy() — a hardened,
	// deny-by-default posture (no network, dropped capabilities,
	// no-new-privileges, read-only rootfs, resource limits, minimal env).
	Confinement *confine.Policy

	EarlyCloseFileDescriptor bool
	// When Debug Mode is set to true, Output result will contain
	// more debug information
	DebugMode bool
}

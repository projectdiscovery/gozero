package confine

import (
	"fmt"
	"path/filepath"
	"sort"
)

// bwrapArgs builds the full bubblewrap (bwrap) command line that wraps argv.
//
// Posture (deny-by-default):
//
//   - --unshare-all creates fresh user, mount, PID, IPC, UTS, cgroup and network
//     namespaces, so the payload sees none of the host's processes, IPC, or
//     network. --share-net is added back only when the policy allows network.
//   - --die-with-parent tears the sandbox down if gozero exits (no orphans).
//   - --new-session detaches the controlling terminal (blocks TIOCSTI injection).
//   - --clearenv drops the inherited environment; only the explicitly allowed
//     variables are re-added with --setenv, so ambient secrets never leak in.
//   - The host root is bind-mounted READ-ONLY so the interpreter and its shared
//     libraries are reachable, then fresh /proc, /dev and a tmpfs /tmp are laid
//     on top. Exactly one path — the workspace — is bound writable. The script's
//     directory is bound read-only (it is normally already covered by the ro
//     root, but binding it explicitly keeps the payload readable even if the
//     script lives on a filesystem the root bind didn't capture).
//   - --cap-drop ALL removes every capability as defense in depth on top of the
//     user namespace.
//
// Flag order matters: bwrap applies binds left-to-right and later binds win for
// overlapping paths, so the read-only root is laid down before the writable
// workspace re-binds over it.
//
// bwrap is a transparent wrapper: stdin/stdout/stderr and the child's exit code
// pass straight through.
func bwrapArgs(bin string, p Policy, workspace, scriptPath string, env map[string]string, argv []string) []string {
	ws := canonicalPath(workspace)

	out := []string{
		bin,
		"--unshare-all",
		"--die-with-parent",
		"--new-session",
		"--clearenv",
	}
	if p.AllowNetwork {
		out = append(out, "--share-net")
	}
	if p.DropAllCapabilities {
		out = append(out, "--cap-drop", "ALL")
	}

	// Read-only host root first, then overlay pseudo-filesystems.
	out = append(out,
		"--ro-bind", "/", "/",
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
	)

	// Single writable path: the workspace.
	if ws != "" {
		out = append(out, "--bind", ws, ws)
	}
	if t := canonicalPath(p.Tmp); t != "" && t != ws {
		out = append(out, "--bind", t, t)
	}
	// Ensure the script's directory is readable even if it sits outside the
	// root bind (idempotent when already covered).
	if scriptPath != "" {
		if dir := canonicalPath(filepath.Dir(scriptPath)); dir != "" && dir != "/" && dir != ws {
			out = append(out, "--ro-bind-try", dir, dir)
		}
	}

	// Non-root identity inside the user namespace.
	if p.RunAsUID >= 0 {
		out = append(out, "--uid", fmt.Sprintf("%d", p.RunAsUID))
	}
	if p.RunAsGID >= 0 {
		out = append(out, "--gid", fmt.Sprintf("%d", p.RunAsGID))
	}

	if ws != "" {
		out = append(out, "--chdir", ws)
	}

	// Re-inject the scrubbed environment deterministically.
	for _, k := range sortedKeys(env) {
		out = append(out, "--setenv", k, env[k])
	}

	out = append(out, "--")
	out = append(out, argv...)
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// canonicalPath resolves symlinks so a bind/profile matches the path the kernel
// actually evaluates, falling back to an absolute/clean path when resolution
// fails (e.g. the path does not exist yet).
func canonicalPath(p string) string {
	if p == "" {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return filepath.Clean(p)
}

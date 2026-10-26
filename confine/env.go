package confine

import (
	"os"
	"sort"
)

// childEnv assembles the environment handed to a confined payload. Precedence,
// low to high:
//
//  1. a minimal base (PATH, plus HOME/TMPDIR pointing at the writable workspace),
//  2. the policy's host allow-list (only vars actually present in the host env),
//  3. the caller's custom vars (validated key shape).
//
// Everything not on the allow-list is dropped, so ambient secrets never reach
// untrusted code. The returned map has no ordering guarantees; use
// envMapToSlice to flatten it.
func childEnv(p Policy, workspace string, custom map[string]string) map[string]string {
	m := make(map[string]string, len(p.AllowedEnv)+len(custom)+3)

	path := os.Getenv("PATH")
	if path == "" {
		path = defaultPATH
	}
	m["PATH"] = path
	if workspace != "" {
		m["HOME"] = workspace
		m["TMPDIR"] = workspace
	}

	for _, k := range p.AllowedEnv {
		if v, ok := os.LookupEnv(k); ok && v != "" {
			m[k] = v
		}
	}

	for k, v := range custom {
		if envKeyOK(k) {
			m[k] = v
		}
	}
	return m
}

// customEnv returns only the validated caller-supplied variables, with no host
// pass-through or base vars. Used by the Docker backend, where the image
// already provides its own base environment (PATH etc.) that we must not
// clobber with host values.
func customEnv(custom map[string]string) map[string]string {
	m := make(map[string]string, len(custom))
	for k, v := range custom {
		if envKeyOK(k) {
			m[k] = v
		}
	}
	return m
}

// envMapToSlice flattens an env map into deterministic "KEY=VALUE" entries.
// Sorting makes generated argv/config stable for tests and logs.
func envMapToSlice(m map[string]string) []string {
	out := make([]string, 0, len(m))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, k+"="+m[k])
	}
	return out
}

// envKeyOK accepts identifier-shaped keys only (^[A-Za-z_][A-Za-z0-9_]*$),
// rejecting anything that could smuggle shell/argv metacharacters into an
// environment assignment.
func envKeyOK(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		switch {
		case r == '_':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

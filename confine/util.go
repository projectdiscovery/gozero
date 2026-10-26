package confine

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// withTimeout wraps ctx with d when d > 0, otherwise returns ctx unchanged with
// a no-op cancel. Lets a Policy.Timeout bound an execution on top of any
// deadline the caller's ctx already carries.
func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}

// hiddenHome returns the canonical home directory that the native backends
// hide from the payload, or "" when it is unknown or is the root directory
// (hiding "/" would hide the whole filesystem).
func hiddenHome() string {
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		return ""
	}
	h = canonicalPath(h)
	if h == "" || h == string(filepath.Separator) {
		return ""
	}
	return h
}

// expandHome resolves a leading "~" against home and canonicalizes the result.
func expandHome(p, home string) string {
	if p == "~" {
		p = home
	} else if strings.HasPrefix(p, "~/") && home != "" {
		p = filepath.Join(home, p[2:])
	}
	return canonicalPath(p)
}

// underDir reports whether p is dir itself or a path below it.
func underDir(p, dir string) bool {
	if p == "" || dir == "" {
		return false
	}
	if p == dir {
		return true
	}
	return strings.HasPrefix(p, strings.TrimSuffix(dir, string(filepath.Separator))+string(filepath.Separator))
}

// systemHiddenDirs lists the directories the native backends hide besides
// the user's own home: the other users' homes and root's home, and on Linux
// the runtime dirs that hold unix sockets (such as the Docker socket). An
// unshared network namespace does not stop a unix socket connect, so these
// sockets must be out of reach to keep the payload away from the daemons.
func systemHiddenDirs() []string {
	switch runtime.GOOS {
	case "linux":
		return []string{"/home", "/root", "/run", "/var/run"}
	case "darwin":
		return []string{"/Users", "/var/root"}
	}
	return nil
}

// hiddenRoots returns the canonical, existing directories hidden from the
// payload: the user's home plus systemHiddenDirs, plus any extra candidates
// the caller adds. Duplicates and directories inside another hidden one are
// dropped, and "/" is never hidden. The result is ordered shortest first, so
// a parent is always handled before a child.
func hiddenRoots(extra ...string) []string {
	candidates := systemHiddenDirs()
	if home := hiddenHome(); home != "" {
		candidates = append(candidates, home)
	}
	candidates = append(candidates, extra...)
	var dirs []string
	for _, c := range candidates {
		resolved, err := filepath.EvalSymlinks(c)
		if err != nil || resolved == string(filepath.Separator) {
			continue
		}
		if st, err := os.Stat(resolved); err != nil || !st.IsDir() {
			continue
		}
		dirs = append(dirs, resolved)
	}
	sort.SliceStable(dirs, func(i, j int) bool { return len(dirs[i]) < len(dirs[j]) })
	var out []string
	for _, d := range dirs {
		if containingRoot(out, d) == "" {
			out = append(out, d)
		}
	}
	return out
}

// containingRoot returns the root in roots that p is in, or "".
func containingRoot(roots []string, p string) string {
	for _, r := range roots {
		if underDir(p, r) {
			return r
		}
	}
	return ""
}

// hiddenReadable returns the canonical paths inside the hidden roots that
// stay readable: the policy's ReadOnlyPaths ("~" is the user's home) plus the
// given extra paths (workspace, temp, script dir). Paths outside every hidden
// root are dropped because they are not hidden. The result is deduplicated and
// keeps input order.
func hiddenReadable(roots []string, readOnly []string, extra ...string) []string {
	if len(roots) == 0 {
		return nil
	}
	home := hiddenHome()
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" || seen[p] || containingRoot(roots, p) == "" {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, p := range readOnly {
		if p != "" {
			add(expandHome(p, home))
		}
	}
	for _, p := range extra {
		if p != "" {
			add(canonicalPath(p))
		}
	}
	return out
}

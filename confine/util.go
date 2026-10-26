package confine

import (
	"context"
	"os"
	"path/filepath"
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

// homeReadable returns the canonical paths under home that stay readable: the
// policy's ReadOnlyPaths plus the given extra paths (workspace, temp, script
// dir). Paths outside home are dropped because they are not hidden. The
// result is deduplicated and keeps input order.
func homeReadable(home string, readOnly []string, extra ...string) []string {
	if home == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" || seen[p] || !underDir(p, home) {
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

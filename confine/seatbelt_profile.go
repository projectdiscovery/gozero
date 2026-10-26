package confine

import (
	"path/filepath"
	"strings"
)

// seatbeltProfile builds the SBPL (Sandbox Profile Language) policy handed to
// macOS sandbox-exec.
//
// Posture: (allow default) opens the world, then file *writes* are denied
// everywhere and re-allowed only under the workspace, the temp dir and a few
// harmless /dev nodes; reads of $HOME, the other users' homes and root's home
// are denied except for the workspace, temp dir, script dir and the policy's
// ReadOnlyPaths allow list; optionally
// all network is denied. This "allow-then-deny" shape is the pragmatic macOS
// state of the art (the same approach shipping browsers use): a hard deny-all
// base is impractical on macOS because the dynamic linker, interpreters and
// system frameworks read from a large, moving set of paths, so we constrain
// the things that actually matter for untrusted execution — reading the
// user's secrets, writing outside the workspace and phoning home.
//
// SBPL is last-match-wins, so the deny rules must come after (allow default)
// and each re-allow must come after its deny.
//
// Paths MUST be canonical: Seatbelt matches realpaths, and on macOS /tmp is a
// symlink to /private/tmp (likewise per-user TMPDIR under /var/folders), so an
// unresolved path silently fails to match and the write is denied.
func seatbeltProfile(p Policy, workspace, scriptPath string) string {
	ws := canonicalPath(workspace)
	tmpC := canonicalPath(p.Tmp)

	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("(allow default)\n")

	if roots := hiddenRoots(); len(roots) > 0 {
		scriptDir := ""
		if scriptPath != "" {
			scriptDir = filepath.Dir(scriptPath)
		}
		readable := hiddenReadable(roots, p.ReadOnlyPaths, ws, tmpC, scriptDir)
		for _, root := range roots {
			b.WriteString("(deny file-read* (subpath " + sbplString(root) + ") (with no-report))\n")
		}
		if len(readable) > 0 {
			// Path lookups (realpath, getcwd) stat every parent directory, so
			// the parents of a re-allowed path keep metadata access. They stay
			// unlistable: file-read-data on them is still denied.
			b.WriteString("(allow file-read-metadata\n")
			for _, dir := range hiddenParents(roots, readable) {
				b.WriteString("  (literal " + sbplString(dir) + ")\n")
			}
			b.WriteString(")\n")
			b.WriteString("(allow file-read*\n")
			for _, r := range readable {
				b.WriteString("  (subpath " + sbplString(r) + ")\n")
			}
			b.WriteString(")\n")
		}
	}

	b.WriteString("(deny file-write* (with no-report))\n")
	b.WriteString("(allow file-write*\n")
	if ws != "" {
		b.WriteString("  (subpath " + sbplString(ws) + ")\n")
	}
	if tmpC != "" && tmpC != ws {
		b.WriteString("  (subpath " + sbplString(tmpC) + ")\n")
	}
	b.WriteString("  (literal \"/dev/null\")\n")
	b.WriteString("  (literal \"/dev/stdout\")\n")
	b.WriteString("  (literal \"/dev/stderr\")\n")
	b.WriteString("  (regex #\"^/dev/tty\")\n")
	// The /usr/bin interpreter shims (xcrun) write a lookup cache into the
	// per-user temp dir; without it every run prints an error on stderr.
	b.WriteString("  (regex #\"^/private/var/folders/[^/]+/[^/]+/T/xcrun_db\")\n")
	b.WriteString(")\n")
	if !p.AllowNetwork {
		b.WriteString("(deny network*)\n")
	}
	return b.String()
}

// hiddenParents returns, for each path, its hidden root and every directory
// between that root and the path (exclusive), deduplicated, in a stable order.
func hiddenParents(roots []string, paths []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		root := containingRoot(roots, p)
		if root == "" {
			continue
		}
		if !seen[root] {
			seen[root] = true
			out = append(out, root)
		}
		for dir := filepath.Dir(p); underDir(dir, root) && !seen[dir]; dir = filepath.Dir(dir) {
			seen[dir] = true
			out = append(out, dir)
		}
	}
	return out
}

// sbplString quotes a path as an SBPL string literal, escaping the only two
// metacharacters valid inside an SBPL "..." (backslash and double quote).
func sbplString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

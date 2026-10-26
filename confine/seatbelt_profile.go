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
// harmless /dev nodes; reads of $HOME are denied except for the workspace,
// temp dir, script dir and the policy's ReadOnlyPaths allow list; optionally
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

	if home := hiddenHome(); home != "" {
		scriptDir := ""
		if scriptPath != "" {
			scriptDir = filepath.Dir(scriptPath)
		}
		readable := homeReadable(home, p.ReadOnlyPaths, ws, tmpC, scriptDir)
		b.WriteString("(deny file-read* (subpath " + sbplString(home) + ") (with no-report))\n")
		if len(readable) > 0 {
			// Path lookups (realpath, getcwd) stat every parent directory, so
			// the parents of a re-allowed path keep metadata access. They stay
			// unlistable: file-read-data on them is still denied.
			b.WriteString("(allow file-read-metadata\n")
			for _, dir := range homeParents(home, readable) {
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
	b.WriteString(")\n")
	if !p.AllowNetwork {
		b.WriteString("(deny network*)\n")
	}
	return b.String()
}

// homeParents returns home and every directory between home and each path in
// paths (exclusive), deduplicated, in a stable order.
func homeParents(home string, paths []string) []string {
	seen := map[string]bool{home: true}
	out := []string{home}
	for _, p := range paths {
		for dir := filepath.Dir(p); underDir(dir, home) && !seen[dir]; dir = filepath.Dir(dir) {
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

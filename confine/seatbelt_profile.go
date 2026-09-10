package confine

import "strings"

// seatbeltProfile builds the SBPL (Sandbox Profile Language) policy handed to
// macOS sandbox-exec.
//
// Posture: (allow default) opens the world, then file *writes* are denied
// everywhere and re-allowed only under the workspace, the temp dir and a few
// harmless /dev nodes; optionally all network is denied. This "allow-then-deny"
// shape is the pragmatic macOS state of the art (the same approach shipping
// browsers use): a hard deny-all base is impractical on macOS because the
// dynamic linker, interpreters and system frameworks read from a large, moving
// set of paths, so we constrain the two things that actually matter for
// untrusted execution — writing outside the workspace and phoning home.
//
// SBPL is last-match-wins, so the deny rules must come after (allow default)
// and the write re-allow must come after the write deny.
//
// Paths MUST be canonical: Seatbelt matches realpaths, and on macOS /tmp is a
// symlink to /private/tmp (likewise per-user TMPDIR under /var/folders), so an
// unresolved path silently fails to match and the write is denied.
func seatbeltProfile(workspace, tmp string, allowNetwork bool) string {
	ws := canonicalPath(workspace)
	tmpC := canonicalPath(tmp)

	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("(allow default)\n")
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
	if !allowNetwork {
		b.WriteString("(deny network*)\n")
	}
	return b.String()
}

// sbplString quotes a path as an SBPL string literal, escaping the only two
// metacharacters valid inside an SBPL "..." (backslash and double quote).
func sbplString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

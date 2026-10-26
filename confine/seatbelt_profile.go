package confine

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// seatbeltProfile builds the SBPL (Sandbox Profile Language) policy handed to
// macOS sandbox-exec.
//
// Posture: (allow default) opens the world, then file *writes* are denied
// everywhere and re-allowed only under the workspace, the temp dir and a few
// harmless /dev nodes; reads of $HOME, the other users' homes, root's home and
// the per-user temp dir are denied except for the workspace, the policy's Tmp
// dir, the script file and the policy's ReadOnlyPaths allow list; optionally
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

	// The per-user temp dir is hidden too: it holds the files of other runs,
	// such as other scans' work dirs and other payloads' scripts.
	if roots := hiddenRoots(userTempDirs()...); len(roots) > 0 {
		readable := hiddenReadable(roots, p.ReadOnlyPaths, ws, tmpC)
		// Only the script file is re-allowed, never its directory: the script
		// usually sits in the shared temp dir next to other runs' files.
		script := ""
		if sp := canonicalPath(scriptPath); containingRoot(roots, sp) != "" && !underDir(sp, ws) {
			script = sp
		}
		for _, root := range roots {
			b.WriteString("(deny file-read* (subpath " + sbplString(root) + ") (with no-report))\n")
		}
		if len(readable) > 0 || script != "" {
			// Path lookups (realpath, getcwd) stat every parent directory, so
			// the parents of a re-allowed path keep metadata access. They stay
			// unlistable: file-read-data on them is still denied.
			b.WriteString("(allow file-read-metadata\n")
			parents := readable
			if script != "" {
				parents = append(append([]string(nil), readable...), script)
			}
			for _, dir := range hiddenParents(roots, parents) {
				b.WriteString("  (literal " + sbplString(dir) + ")\n")
			}
			b.WriteString(")\n")
			b.WriteString("(allow file-read*\n")
			for _, r := range readable {
				b.WriteString("  (subpath " + sbplString(r) + ")\n")
			}
			if script != "" {
				b.WriteString("  (literal " + sbplString(script) + ")\n")
			}
			b.WriteString(")\n")
		}
		// The /usr/bin interpreter shims (xcrun) read their lookup cache from
		// the per-user temp dir; without it they fall back to xcodebuild and
		// print errors on stderr. The same file is the one write allowed below.
		b.WriteString("(allow file-read* (regex " + xcrunDBRegex + "))\n")
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
	b.WriteString("  (regex " + xcrunDBRegex + ")\n")
	b.WriteString(")\n")
	if !p.AllowNetwork {
		b.WriteString("(deny network*)\n")
	}
	return b.String()
}

// xcrunDBRegex matches the xcrun lookup cache in the per-user temp dir.
const xcrunDBRegex = `#"^/private/var/folders/[^/]+/[^/]+/T/xcrun_db$"`

// darwinUserTempDir is the per-user temp dir that macOS gives each user under
// /var/folders (confstr DARWIN_USER_TEMP_DIR). It can differ from $TMPDIR when
// the caller overrides TMPDIR. Read once, with an absolute getconf path.
var darwinUserTempDir = sync.OnceValue(func() string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	out, err := exec.Command("/usr/bin/getconf", "DARWIN_USER_TEMP_DIR").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
})

// userTempDirs returns the canonical per-user temp dirs that Seatbelt hides:
// $TMPDIR (os.TempDir) and the macOS per-user temp dir. A dir less than two
// levels deep (such as /private) is never hidden, because it holds system
// files; hiddenRoots drops dirs that do not exist.
func userTempDirs() []string {
	var out []string
	for _, d := range []string{os.TempDir(), darwinUserTempDir()} {
		if d == "" {
			continue
		}
		c := canonicalPath(d)
		if strings.Count(strings.Trim(c, string(filepath.Separator)), string(filepath.Separator)) < 1 {
			continue
		}
		out = append(out, c)
	}
	return out
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

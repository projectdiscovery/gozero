package confine

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// containsSeq reports whether sub appears as a contiguous subsequence of s.
func containsSeq(s, sub []string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if equalSlice(s[i:i+len(sub)], sub) {
			return true
		}
	}
	return false
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestBwrapArgsHardenedByDefault(t *testing.T) {
	ws := t.TempDir()
	p := DefaultPolicy()
	p.Tmp = ws // avoid a second writable bind for a distinct temp dir
	argv := []string{"/usr/bin/python3", "/tmp/script.py", "--flag"}
	env := map[string]string{"PATH": "/usr/bin", "FOO": "bar"}

	got := bwrapArgs("/usr/bin/bwrap", p, ws, "/tmp/script.py", env, argv)
	cws := canonicalPath(ws)

	// Core isolation flags.
	assert.Equal(t, "/usr/bin/bwrap", got[0])
	for _, flag := range []string{"--unshare-all", "--die-with-parent", "--new-session", "--clearenv"} {
		assert.Contains(t, got, flag, "missing hardening flag %s", flag)
	}
	assert.True(t, containsSeq(got, []string{"--cap-drop", "ALL"}), "must drop all capabilities")
	assert.True(t, containsSeq(got, []string{"--ro-bind", "/", "/"}), "host root must be read-only")
	assert.True(t, containsSeq(got, []string{"--proc", "/proc"}))
	assert.True(t, containsSeq(got, []string{"--dev", "/dev"}))
	assert.True(t, containsSeq(got, []string{"--tmpfs", "/tmp"}))
	assert.True(t, containsSeq(got, []string{"--bind", cws, cws}), "workspace must be the writable bind")
	assert.True(t, containsSeq(got, []string{"--chdir", cws}))

	// Environment is re-injected deterministically (sorted), never inherited.
	assert.True(t, containsSeq(got, []string{"--setenv", "FOO", "bar"}))
	assert.True(t, containsSeq(got, []string{"--setenv", "PATH", "/usr/bin"}))
	fooIdx := indexOf(got, "FOO")
	pathIdx := indexOf(got, "PATH")
	assert.Less(t, fooIdx, pathIdx, "setenv keys must be sorted")

	// No network by default.
	assert.NotContains(t, got, "--share-net")

	// Command follows the -- terminator, in order, and unchanged.
	dashIdx := lastIndexOf(got, "--")
	require.NotEqual(t, -1, dashIdx)
	assert.Equal(t, argv, got[dashIdx+1:], "argv must be passed verbatim after --")
}

func TestBwrapArgsZeroPolicyDropsCapabilities(t *testing.T) {
	got := bwrapArgs("bwrap", Policy{}.normalized(), t.TempDir(), "", nil, []string{"sh"})
	assert.True(t, containsSeq(got, []string{"--cap-drop", "ALL"}), "zero policy must drop all capabilities")

	p := DefaultPolicy()
	p.AllowCapabilities = true
	assert.NotContains(t, bwrapArgs("bwrap", p, t.TempDir(), "", nil, []string{"sh"}), "--cap-drop")
}

func TestBwrapArgsHidesHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bwrap runs only on Linux and takes POSIX paths")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	ch := canonicalPath(home)
	pyenv := filepath.Join(ch, ".pyenv")
	ws := filepath.Join(ch, "ws")

	p := DefaultPolicy()
	p.ReadOnlyPaths = []string{"~/.pyenv", "/usr/local"}
	got := bwrapArgs("bwrap", p, ws, "", nil, []string{"sh"})

	tmpfsIdx := indexOfSeq(got, []string{"--tmpfs", ch})
	require.NotEqual(t, -1, tmpfsIdx, "home must be covered by a tmpfs")
	assert.Greater(t, tmpfsIdx, indexOfSeq(got, []string{"--ro-bind", "/", "/"}), "tmpfs must come after the root bind")
	roIdx := indexOfSeq(got, []string{"--ro-bind-try", pyenv, pyenv})
	assert.Greater(t, roIdx, tmpfsIdx, "allow-listed home path is bound back read-only after the tmpfs")
	assert.Greater(t, indexOfSeq(got, []string{"--bind", ws, ws}), tmpfsIdx, "workspace under home is bound after the tmpfs")
	assert.False(t, containsSeq(got, []string{"--ro-bind-try", "/usr/local", "/usr/local"}), "paths outside home are not hidden and need no bind")
}

func TestBwrapArgsNetworkToggle(t *testing.T) {
	ws := t.TempDir()
	p := DefaultPolicy()
	p.AllowNetwork = true
	got := bwrapArgs("bwrap", p, ws, "", nil, []string{"sh"})
	assert.Contains(t, got, "--share-net", "network must be re-shared when allowed")
}

func TestBwrapArgsNonRootIdentity(t *testing.T) {
	ws := t.TempDir()
	p := DefaultPolicy()
	p.RunAsUID = 1000
	p.RunAsGID = 1000
	got := bwrapArgs("bwrap", p, ws, "", nil, []string{"sh"})
	assert.True(t, containsSeq(got, []string{"--uid", "1000"}))
	assert.True(t, containsSeq(got, []string{"--gid", "1000"}))
}

func indexOfSeq(s, sub []string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if equalSlice(s[i:i+len(sub)], sub) {
			return i
		}
	}
	return -1
}

func indexOf(s []string, v string) int {
	for i := range s {
		if s[i] == v {
			return i
		}
	}
	return -1
}

func lastIndexOf(s []string, v string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == v {
			return i
		}
	}
	return -1
}

// ensure the joined form is shell-inspectable (used in a couple of assertions).
var _ = strings.Join

func TestBwrapArgsHidesSystemDirs(t *testing.T) {
	p := DefaultPolicy()
	got := bwrapArgs("bwrap", p, t.TempDir(), "", nil, []string{"sh"})
	for _, root := range hiddenRoots() {
		assert.True(t, containsSeq(got, []string{"--tmpfs", root}), "%s must be covered by a tmpfs", root)
	}
	if runtime.GOOS == "linux" {
		if run, err := filepath.EvalSymlinks("/run"); err == nil {
			assert.True(t, containsSeq(got, []string{"--tmpfs", run}), "runtime sockets (Docker) must be hidden")
		}
	}
}

func TestHiddenRootsDropsNested(t *testing.T) {
	roots := hiddenRoots()
	for i, a := range roots {
		assert.NotEqual(t, string(filepath.Separator), a)
		for j, b := range roots {
			if i != j {
				assert.False(t, underDir(b, a), "%s is nested in %s", b, a)
			}
		}
	}
}

// The script usually sits directly in the host temp dir, next to the
// workspace. Only the script file may be bound, and before the workspace, so
// the host temp dir stays hidden and the workspace stays writable.
func TestBwrapArgsBindsOnlyTheScript(t *testing.T) {
	dir := canonicalPath(t.TempDir())
	ws := filepath.Join(dir, "ws")
	script := filepath.Join(dir, "script.sh")
	got := bwrapArgs("bwrap", DefaultPolicy(), ws, script, nil, []string{"sh", script})

	assert.False(t, containsSeq(got, []string{"--ro-bind-try", dir, dir}), "the script dir must not be bound")
	scriptIdx := indexOfSeq(got, []string{"--ro-bind-try", script, script})
	require.NotEqual(t, -1, scriptIdx, "the script file must be bound read-only")
	assert.Less(t, scriptIdx, indexOfSeq(got, []string{"--bind", ws, ws}), "the workspace bind must come last")
}

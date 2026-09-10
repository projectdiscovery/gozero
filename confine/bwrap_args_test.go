package confine

import (
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

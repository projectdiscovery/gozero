package confine

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeatbeltProfileConfinesWrites(t *testing.T) {
	ws := t.TempDir()
	profile := seatbeltProfile(Policy{Tmp: ws}, ws, "")

	assert.Contains(t, profile, "(version 1)")
	assert.Contains(t, profile, "(allow default)")
	assert.Contains(t, profile, "(deny file-write* (with no-report))")
	assert.Contains(t, profile, "(subpath "+sbplString(canonicalPath(ws))+")")
	assert.Contains(t, profile, "(deny network*)", "network must be denied when not allowed")
}

func TestSeatbeltProfileNetworkToggle(t *testing.T) {
	ws := t.TempDir()
	assert.NotContains(t, seatbeltProfile(Policy{Tmp: ws, AllowNetwork: true}, ws, ""), "(deny network*)")
	assert.Contains(t, seatbeltProfile(Policy{Tmp: ws}, ws, ""), "(deny network*)")
}

func TestSbplStringEscapes(t *testing.T) {
	assert.Equal(t, `"/a/b"`, sbplString("/a/b"))
	assert.Equal(t, `"/a\"b"`, sbplString(`/a"b`))
	assert.Equal(t, `"/a\\b"`, sbplString(`/a\b`))
}

// The deny-all base must precede the write re-allow (SBPL is last-match-wins).
func TestSeatbeltProfileRuleOrder(t *testing.T) {
	ws := t.TempDir()
	profile := seatbeltProfile(Policy{Tmp: ws}, ws, "")
	denyIdx := strings.Index(profile, "(deny file-write*")
	allowIdx := strings.Index(profile, "(allow file-write*")
	assert.Less(t, denyIdx, allowIdx, "write deny must come before the workspace re-allow")
}

func TestSeatbeltProfileHidesHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	ch := canonicalPath(home)
	ws := filepath.Join(ch, "work", "ws")

	p := Policy{ReadOnlyPaths: []string{"~/.pyenv", "/opt/homebrew"}}
	profile := seatbeltProfile(p, ws, filepath.Join(ch, "src", "s.py"))

	// The test home sits in the temp dir, which is hidden too; the deny then
	// names the outermost hidden dir that holds the home.
	root := containingRoot(hiddenRoots(userTempDirs()...), ch)
	require.NotEmpty(t, root, "home must be inside a hidden root")
	deny := "(deny file-read* (subpath " + sbplString(root) + ") (with no-report))"
	assert.Contains(t, profile, deny, "home reads must be denied")
	allowIdx := strings.Index(profile, "(allow file-read*")
	assert.Greater(t, allowIdx, strings.Index(profile, deny), "re-allow must follow the deny")
	allow := profile[allowIdx:]
	assert.Contains(t, allow, "(subpath "+sbplString(filepath.Join(ch, ".pyenv"))+")", "allow-listed path is readable")
	assert.Contains(t, allow, "(subpath "+sbplString(ws)+")", "workspace under home is readable")
	assert.Contains(t, allow, "(literal "+sbplString(filepath.Join(ch, "src", "s.py"))+")", "script file under home is readable")
	assert.NotContains(t, allow, "(subpath "+sbplString(filepath.Join(ch, "src"))+")", "script dir under home stays hidden")
	assert.NotContains(t, profile, "/opt/homebrew", "paths outside home are not hidden and need no rule")
	// Parents of a re-allowed path keep metadata access only.
	assert.Contains(t, profile, "(literal "+sbplString(filepath.Join(ch, "work"))+")")
}

func TestSeatbeltProfileHidesSystemDirs(t *testing.T) {
	ws := t.TempDir()
	profile := seatbeltProfile(Policy{}, ws, "")
	for _, root := range hiddenRoots() {
		assert.Contains(t, profile, "(deny file-read* (subpath "+sbplString(root)+") (with no-report))", "%s must be hidden", root)
	}
	if runtime.GOOS == "darwin" {
		assert.Contains(t, profile, `(subpath "/Users")`, "other users' homes must be hidden")
	}
}

// The per-user temp dir holds other runs' files (other scans' work dirs,
// other payloads' scripts), so it is hidden, with the rest of the per-user
// dir (C/ caches, 0/) and the shared /tmp. Only the run's own workspace and
// script file come back, plus the xcrun cache the /usr/bin shims need.
func TestSeatbeltProfileHidesUserTemp(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Seatbelt and the per-user temp dir exist only on macOS")
	}
	tmp := canonicalPath(os.TempDir())
	ws := canonicalPath(t.TempDir())
	scriptDir := canonicalPath(t.TempDir())
	script := filepath.Join(scriptDir, "s.sh")
	require.NoError(t, os.WriteFile(script, []byte("true\n"), 0o600))

	profile := seatbeltProfile(Policy{}, ws, script)

	root := containingRoot(hiddenRoots(userTempDirs()...), tmp)
	require.NotEmpty(t, root, "the temp dir must be inside a hidden root")
	deny := "(deny file-read* (subpath " + sbplString(root) + ") (with no-report))"
	assert.Contains(t, profile, deny, "temp dir reads must be denied")
	allowIdx := strings.Index(profile, "(allow file-read*")
	assert.Greater(t, allowIdx, strings.Index(profile, deny), "re-allow must follow the deny")
	allow := profile[allowIdx:strings.Index(profile, "(deny file-write*")]
	assert.Contains(t, allow, "(subpath "+sbplString(ws)+")", "workspace is readable")
	assert.Contains(t, allow, "(literal "+sbplString(script)+")", "script file is readable")
	assert.NotContains(t, allow, sbplString(scriptDir)+")", "script dir stays hidden")
	assert.NotContains(t, allow, "(subpath "+sbplString(tmp)+")", "temp dir stays hidden")
	assert.Contains(t, allow, "(regex "+xcrunDBRegex+")", "xcrun cache is readable")

	if runtime.GOOS == "darwin" {
		assert.Contains(t, profile, `(deny file-read* (subpath "/private/tmp") (with no-report))`, "the shared /tmp must be hidden")
		ud := canonicalPath(darwinUserDir())
		require.NotEmpty(t, ud)
		assert.Contains(t, profile, "(deny file-read* (subpath "+sbplString(ud)+") (with no-report))", "the whole per-user dir (T, C, 0) must be hidden")
		assert.NotContains(t, allow, "(subpath "+sbplString(filepath.Join(ud, "C"))+")", "the per-user cache dir stays hidden")
	}
}

package confine

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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

	deny := "(deny file-read* (subpath " + sbplString(ch) + ") (with no-report))"
	assert.Contains(t, profile, deny, "home reads must be denied")
	allowIdx := strings.Index(profile, "(allow file-read*")
	assert.Greater(t, allowIdx, strings.Index(profile, deny), "re-allow must follow the deny")
	allow := profile[allowIdx:]
	assert.Contains(t, allow, "(subpath "+sbplString(filepath.Join(ch, ".pyenv"))+")", "allow-listed path is readable")
	assert.Contains(t, allow, "(subpath "+sbplString(ws)+")", "workspace under home is readable")
	assert.Contains(t, allow, "(subpath "+sbplString(filepath.Join(ch, "src"))+")", "script dir under home is readable")
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

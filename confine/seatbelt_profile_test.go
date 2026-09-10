package confine

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSeatbeltProfileConfinesWrites(t *testing.T) {
	ws := t.TempDir()
	profile := seatbeltProfile(ws, ws, false)

	assert.Contains(t, profile, "(version 1)")
	assert.Contains(t, profile, "(allow default)")
	assert.Contains(t, profile, "(deny file-write* (with no-report))")
	assert.Contains(t, profile, "(subpath "+sbplString(canonicalPath(ws))+")")
	assert.Contains(t, profile, "(deny network*)", "network must be denied when not allowed")
}

func TestSeatbeltProfileNetworkToggle(t *testing.T) {
	ws := t.TempDir()
	assert.NotContains(t, seatbeltProfile(ws, ws, true), "(deny network*)")
	assert.Contains(t, seatbeltProfile(ws, ws, false), "(deny network*)")
}

func TestSbplStringEscapes(t *testing.T) {
	assert.Equal(t, `"/a/b"`, sbplString("/a/b"))
	assert.Equal(t, `"/a\"b"`, sbplString(`/a"b`))
	assert.Equal(t, `"/a\\b"`, sbplString(`/a\b`))
}

// The deny-all base must precede the write re-allow (SBPL is last-match-wins).
func TestSeatbeltProfileRuleOrder(t *testing.T) {
	ws := t.TempDir()
	profile := seatbeltProfile(ws, ws, false)
	denyIdx := strings.Index(profile, "(deny file-write*")
	allowIdx := strings.Index(profile, "(allow file-write*")
	assert.Less(t, denyIdx, allowIdx, "write deny must come before the workspace re-allow")
}

package confine

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChildEnvScrubsAmbientSecrets(t *testing.T) {
	t.Setenv("LANG", "en_US.UTF-8")
	t.Setenv("GOZERO_SECRET_TOKEN", "s3cr3t") // not on the allow-list

	p := DefaultPolicy()
	ws := "/work"
	env := childEnv(p, ws, map[string]string{"USER_VAR": "v", "bad-key": "x"})

	assert.Equal(t, ws, env["HOME"], "HOME points at the writable workspace")
	assert.Equal(t, ws, env["TMPDIR"])
	assert.NotEmpty(t, env["PATH"])
	assert.Equal(t, "en_US.UTF-8", env["LANG"], "allow-listed host var passes through")
	assert.Equal(t, "v", env["USER_VAR"], "valid custom var passes through")

	_, leaked := env["GOZERO_SECRET_TOKEN"]
	assert.False(t, leaked, "ambient secret must not leak into the payload")
	_, bad := env["bad-key"]
	assert.False(t, bad, "invalid env key must be dropped")
}

func TestCustomEnvOnlyKeepsValidKeys(t *testing.T) {
	got := customEnv(map[string]string{"A": "1", "bad-key": "x", "B2": "2", "": "y"})
	assert.Equal(t, map[string]string{"A": "1", "B2": "2"}, got)
}

func TestEnvMapToSliceIsSorted(t *testing.T) {
	got := envMapToSlice(map[string]string{"B": "2", "A": "1", "C": "3"})
	assert.Equal(t, []string{"A=1", "B=2", "C=3"}, got)
}

func TestEnvKeyOK(t *testing.T) {
	cases := map[string]bool{
		"PATH": true, "_X": true, "A1": true, "a_b_2": true,
		"": false, "1A": false, "A-B": false, "A B": false, "A=B": false, "FOO$": false,
	}
	for k, want := range cases {
		assert.Equalf(t, want, envKeyOK(k), "envKeyOK(%q)", k)
	}
}

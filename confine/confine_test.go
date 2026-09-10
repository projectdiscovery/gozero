package confine

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultPolicyIsHardened(t *testing.T) {
	p := DefaultPolicy()
	assert.Equal(t, BackendAuto, p.Backend)
	assert.False(t, p.AllowNetwork, "network must be denied by default")
	assert.True(t, p.DropAllCapabilities)
	assert.True(t, p.NoNewPrivileges)
	assert.True(t, p.ReadonlyRootfs)
	assert.Equal(t, defaultPidsLimit, p.PidsLimit)
	assert.Equal(t, defaultMemoryBytes, p.MemoryBytes)
	assert.Equal(t, defaultNanoCPUs, p.NanoCPUs)
	assert.Equal(t, -1, p.RunAsUID, "must not default to root")
	assert.Equal(t, -1, p.RunAsGID)
	assert.NotEmpty(t, p.AllowedEnv)
}

func TestNormalizedFillsSparsePolicy(t *testing.T) {
	// A caller who only sets a backend still gets every hardened default.
	got := Policy{Backend: BackendDocker}.normalized()
	assert.Equal(t, BackendDocker, got.Backend)
	assert.Equal(t, defaultPidsLimit, got.PidsLimit)
	assert.Equal(t, defaultMemoryBytes, got.MemoryBytes)
	assert.Equal(t, defaultNanoCPUs, got.NanoCPUs)
	assert.Equal(t, defaultDockerImage, got.DockerImage)
	assert.Equal(t, defaultPullTimeout, got.PullTimeout)
	assert.NotEmpty(t, got.Tmp)
	assert.NotNil(t, got.Logger)
	// A zero-value uid/gid must be treated as "unset" and never forced to root.
	assert.Equal(t, -1, got.RunAsUID)
	assert.Equal(t, -1, got.RunAsGID)
}

// TestNewNilPolicyDoesNotPanic guards the regression where New(nil) used
// DefaultPolicy() without normalizing it, leaving Logger nil and panicking in
// the backend probe. It must return cleanly (a confiner or a fail-closed error).
func TestNewNilPolicyDoesNotPanic(t *testing.T) {
	c, err := New(nil)
	if err != nil {
		assert.ErrorIs(t, err, ErrConfinementUnavailable)
		assert.Nil(t, c)
		return
	}
	require.NotNil(t, c)
	_ = c.Close()
}

func TestNewUnsupportedBackendFailsClosed(t *testing.T) {
	c, err := New(&Policy{Backend: Backend("nonsense")})
	assert.Nil(t, c)
	assert.ErrorIs(t, err, ErrUnsupportedBackend)
}

func TestNewHostBackendIsExplicitOptOut(t *testing.T) {
	// BackendHost is the only way to get an unconfined executor, and it must be
	// asked for by name — never returned as a fallback.
	c, err := New(&Policy{Backend: BackendHost})
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, "host", c.Name())
	assert.NoError(t, c.Close())
}

func TestHostConfinerRejectsEmptyCommand(t *testing.T) {
	_, err := hostConfiner{}.Run(context.Background(), Spec{})
	assert.ErrorIs(t, err, ErrNoCommand)
}

// TestNewNativeFailsClosedWhenUnavailable asserts the core anti-escape
// property: when a native backend is requested but the mechanism is not present
// on this host, New returns ErrConfinementUnavailable rather than a permissive
// confiner. It is skipped when the mechanism happens to be installed.
func TestNewNativeFailsClosedWhenUnavailable(t *testing.T) {
	c, err := New(&Policy{Backend: BackendAuto})
	if err == nil {
		require.NotNil(t, c)
		_ = c.Close()
		t.Skipf("a native confiner (%s) is available on this host; fail-closed path not exercised", c.Name())
	}
	assert.Truef(t, errors.Is(err, ErrConfinementUnavailable),
		"expected ErrConfinementUnavailable, got %v", err)
	assert.Nil(t, c)
}

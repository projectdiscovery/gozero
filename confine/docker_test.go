package confine

import (
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDockerHostConfigHardenedByDefault(t *testing.T) {
	hc := dockerHostConfig(DefaultPolicy())

	assert.Equal(t, container.NetworkMode("none"), hc.NetworkMode, "no network by default")
	assert.Equal(t, []string{"ALL"}, hc.CapDrop, "all capabilities dropped")
	assert.Contains(t, hc.SecurityOpt, "no-new-privileges:true")
	assert.True(t, hc.ReadonlyRootfs, "rootfs must be read-only")
	assert.False(t, hc.Privileged, "must never be privileged")
	assert.Equal(t, container.CgroupnsModePrivate, hc.CgroupnsMode)
	assert.Equal(t, container.IPCModePrivate, hc.IpcMode)
	require.NotNil(t, hc.PidsLimit)
	assert.Equal(t, defaultPidsLimit, *hc.PidsLimit)
	assert.Equal(t, defaultMemoryBytes, hc.Memory)
	assert.Equal(t, defaultNanoCPUs, hc.NanoCPUs)
	assert.Contains(t, hc.Tmpfs, containerWorkDir)
	assert.Contains(t, hc.Tmpfs, "/tmp")
}

// TestDockerSparsePolicyIsHardened guards the fail-open regression where the
// security switches were opt-in bools: a policy that only sets Backend must
// still drop every capability, set no-new-privileges, use a read-only rootfs
// and run as a non-root user.
func TestDockerSparsePolicyIsHardened(t *testing.T) {
	p := Policy{Backend: BackendDocker}.normalized()
	hc := dockerHostConfig(p)
	assert.Equal(t, container.NetworkMode("none"), hc.NetworkMode)
	assert.Equal(t, []string{"ALL"}, hc.CapDrop)
	assert.Contains(t, hc.SecurityOpt, "no-new-privileges:true")
	assert.True(t, hc.ReadonlyRootfs)
	assert.Equal(t, "65534:65534", dockerUser(p))
}

func TestDockerHostConfigOptOuts(t *testing.T) {
	p := DefaultPolicy()
	p.AllowCapabilities = true
	p.AllowNewPrivileges = true
	p.WritableRootfs = true
	hc := dockerHostConfig(p)
	assert.Empty(t, hc.CapDrop)
	assert.NotContains(t, hc.SecurityOpt, "no-new-privileges:true")
	assert.False(t, hc.ReadonlyRootfs)
}

func TestDockerUser(t *testing.T) {
	p := DefaultPolicy()
	assert.Equal(t, "65534:65534", dockerUser(p), "default must be nobody, not the image user")
	p.RunAsUID, p.RunAsGID = 1000, 1001
	assert.Equal(t, "1000:1001", dockerUser(p))
	p.RunAsGID = -1
	assert.Equal(t, "1000", dockerUser(p))
	p.DockerUser = "root"
	assert.Equal(t, "root", dockerUser(p), "DockerUser overrides everything")
}

func TestDockerHostConfigNetworkToggle(t *testing.T) {
	p := DefaultPolicy()
	p.AllowNetwork = true
	hc := dockerHostConfig(p)
	assert.NotEqual(t, container.NetworkMode("none"), hc.NetworkMode, "network must not be forced to none when allowed")
}

func TestDockerContainerConfigStdinGating(t *testing.T) {
	cfg := dockerContainerConfig("alpine", []string{"sh", "/gozero-src/s"}, "/work", []string{"HOME=/work"}, "", false)
	assert.Equal(t, "alpine", cfg.Image)
	assert.Equal(t, "/work", cfg.WorkingDir)
	assert.True(t, cfg.AttachStdout)
	assert.True(t, cfg.AttachStderr)
	assert.False(t, cfg.OpenStdin)
	assert.False(t, cfg.AttachStdin)
	assert.Empty(t, cfg.User)

	withStdin := dockerContainerConfig("alpine", []string{"sh"}, "/work", nil, "1000:1000", true)
	assert.True(t, withStdin.OpenStdin)
	assert.True(t, withStdin.AttachStdin)
	assert.True(t, withStdin.StdinOnce)
	assert.Equal(t, "1000:1000", withStdin.User)
}

func TestRemapScript(t *testing.T) {
	argv := []string{"/usr/bin/python3", "/host/tmp/abc.py", "--flag", "value"}
	got := remapScript(argv, "/host/tmp/abc.py", "/gozero-src/abc.py", "python3", true)
	assert.Equal(t, []string{"python3", "/gozero-src/abc.py", "--flag", "value"}, got)

	// Without interpreter replacement, only the script path is remapped.
	got2 := remapScript(argv, "/host/tmp/abc.py", "/gozero-src/abc.py", "python3", false)
	assert.Equal(t, "/usr/bin/python3", got2[0])
	assert.Equal(t, "/gozero-src/abc.py", got2[1])

	// Original argv is not mutated.
	assert.Equal(t, "/host/tmp/abc.py", argv[1])
}

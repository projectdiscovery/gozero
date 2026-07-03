package confine

import (
	"archive/tar"
	"io"
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

// tarSingleFile is the heredoc-free source-injection primitive: verify the
// archive round-trips exactly, with the requested name and mode.
func TestTarSingleFileRoundTrip(t *testing.T) {
	// Content deliberately contains a bare "EOF" line and shell metacharacters
	// that would break a heredoc/shell-interpolation approach.
	content := []byte("print('hi')\nEOF\n$(rm -rf /)\n`id`\n")
	r, err := tarSingleFile("script.py", content, 0o755)
	require.NoError(t, err)

	tr := tar.NewReader(r)
	hdr, err := tr.Next()
	require.NoError(t, err)
	assert.Equal(t, "script.py", hdr.Name)
	assert.Equal(t, int64(0o755), hdr.Mode)
	assert.Equal(t, int64(len(content)), hdr.Size)

	got, err := io.ReadAll(tr)
	require.NoError(t, err)
	assert.Equal(t, content, got, "source must round-trip byte-for-byte")

	_, err = tr.Next()
	assert.ErrorIs(t, err, io.EOF, "archive must contain exactly one file")
}

// tarSourceTree must carry the containing directory so extraction at "/" creates
// it; CopyToContainer requires the destination directory to pre-exist.
func TestTarSourceTreeIncludesDir(t *testing.T) {
	content := []byte("echo hi\n")
	r, err := tarSourceTree("gozero-src", "script.sh", content, 0o755)
	require.NoError(t, err)

	tr := tar.NewReader(r)

	dir, err := tr.Next()
	require.NoError(t, err)
	assert.Equal(t, "gozero-src/", dir.Name)
	assert.Equal(t, byte(tar.TypeDir), dir.Typeflag)

	file, err := tr.Next()
	require.NoError(t, err)
	assert.Equal(t, "gozero-src/script.sh", file.Name)
	assert.Equal(t, int64(0o755), file.Mode)

	got, err := io.ReadAll(tr)
	require.NoError(t, err)
	assert.Equal(t, content, got, "source must round-trip byte-for-byte")

	_, err = tr.Next()
	assert.ErrorIs(t, err, io.EOF, "archive must contain exactly the dir and file")
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

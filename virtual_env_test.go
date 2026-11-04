//nolint:depguard,exhaustruct,exhaustruct_v5 // no depguard allow list exists; zero values are intended
package gozero_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/projectdiscovery/gozero"
	"github.com/projectdiscovery/gozero/sandbox"
	"github.com/projectdiscovery/gozero/types"
	osutils "github.com/projectdiscovery/utils/os"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEvalWithVirtualEnvDockerMatchesEval checks that the Docker container
// runs a source as Eval does: the engine gets Options.Args, the source gets
// the call arguments, the input is stdin, and its variables are environment
// variables.
//
//nolint:paralleltest // newFakeDockerd sets process-wide environment variables
func TestEvalWithVirtualEnvDockerMatchesEval(t *testing.T) {
	skipOnWindows(t)

	engine := newEngine(t)
	args := []string{"hello", "two  words"}

	// With Options.Args -e, the engine stops at false.
	const script = `echo "$# args: $*"; echo "FOO: $FOO"; read line; echo "stdin: $line"; false; echo "no -e"`

	want, err := engine.Eval(t.Context(), newSource(t, script), newInput(t), args...)
	require.Error(t, err, "Eval of a source that exits 1")
	require.Equal(t, "2 args: hello two  words\nFOO: bar\nstdin: from-stdin\n", want.Stdout.String(), "Eval output")

	dockerd := newFakeDockerd(t)
	_, err = engine.EvalWithVirtualEnv(t.Context(), gozero.VirtualEnvDocker,
		newSource(t, script), newInput(t), dockerConfig(), args...)
	require.NoError(t, err)

	created, stdin := dockerd.recorded()
	assert.True(t, created.AttachStdin && created.OpenStdin && created.StdinOnce,
		"container stdin is not attached, open and closed after the input")

	output, exitCode := runLikeContainer(t, created, stdin)
	assert.Equal(t, want.Stdout.String(), output, "container output of command %q", created.Cmd)
	assert.Equal(t, want.GetExitCode(), exitCode, "container exit code")
	assert.True(t, dockerd.removed(), "container is not removed")
}

// TestEvalWithVirtualEnvDockerShebang checks that, unlike Eval, Docker runs a
// source with a shebang directly, without the engine and Options.Args, and
// still passes the call arguments and stdin.
//
//nolint:paralleltest // newFakeDockerd sets process-wide environment variables
func TestEvalWithVirtualEnvDockerShebang(t *testing.T) {
	skipOnWindows(t)

	const script = "#!/bin/sh\n" + `echo "$# args: $*"; read line; echo "stdin: $line"; false; echo "no -e"`

	dockerd := newFakeDockerd(t)
	_, err := newEngine(t).EvalWithVirtualEnv(t.Context(), gozero.VirtualEnvDocker,
		newSource(t, script), newInput(t), dockerConfig(), "hello", "two  words")
	require.NoError(t, err)

	created, stdin := dockerd.recorded()
	output, _ := runLikeContainer(t, created, stdin)
	assert.Equal(t, "2 args: hello two  words\nstdin: from-stdin\nno -e\n", output,
		"container output of command %q", created.Cmd)
}

// TestDockerRunSourceInterpreterArgs checks that RunSource still accepts an
// interpreter with arguments, and runs the source without stdin.
//
//nolint:paralleltest // newFakeDockerd sets process-wide environment variables
func TestDockerRunSourceInterpreterArgs(t *testing.T) {
	skipOnWindows(t)

	dockerd := newFakeDockerd(t)

	docker, err := sandbox.NewDockerSandbox(t.Context(), dockerConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = docker.Clear() })

	_, err = docker.RunSource(t.Context(), `echo start; false; echo "no -e"`, "sh -e")
	require.NoError(t, err)

	created, _ := dockerd.recorded()
	assert.False(t, created.OpenStdin, "container stdin is open")

	output, _ := runLikeContainer(t, created, "")
	assert.Equal(t, "start\n", output, "container output of command %q", created.Cmd)
}

func skipOnWindows(t *testing.T) {
	t.Helper()

	if osutils.IsWindows() {
		t.Skip("the fake docker CLI is a POSIX shell script")
	}
}

// newEngine returns an executor that runs sources with sh -e.
func newEngine(t *testing.T) *gozero.Gozero {
	t.Helper()

	engine, err := gozero.New(&gozero.Options{Engines: []string{"sh"}, Args: []string{"-e"}})
	require.NoError(t, err)

	return engine
}

// newSource returns a source with content that is removed when the test ends.
func newSource(t *testing.T, content string) *gozero.Source {
	t.Helper()

	src, err := gozero.NewSourceWithString(content, "", "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = src.Cleanup() })

	return src
}

// newInput returns an input source with one line of stdin and the variable
// FOO=bar.
func newInput(t *testing.T) *gozero.Source {
	t.Helper()

	input := newSource(t, "from-stdin\n")
	input.AddVariable(types.Variable{Name: "FOO", Value: "bar"})

	return input
}

// dockerConfig returns a sandbox configuration for the fake Docker API.
// EvalWithVirtualEnv changes the configuration, so each call needs its own.
func dockerConfig() *sandbox.DockerConfiguration {
	return &sandbox.DockerConfiguration{Image: "alpine:3", WorkingDir: "/tmp", Timeout: 10 * time.Second}
}

var containerScriptPath = regexp.MustCompile(`/tmp/gozero_script_\d+`)

// runLikeContainer runs the command of the created container with the host's
// /bin/sh, its environment and stdin, and returns the standard output and the
// exit code.
func runLikeContainer(t *testing.T, created container.Config, stdin string) (string, int) {
	t.Helper()
	require.NotEmpty(t, created.Cmd, "container command")

	for _, arg := range created.Cmd {
		for _, path := range containerScriptPath.FindAllString(arg, -1) {
			t.Cleanup(func() { _ = os.Remove(path) })
		}
	}

	var stdout bytes.Buffer

	//nolint:gosec // runs the command that the sandbox sent to the fake Docker API
	cmd := exec.CommandContext(t.Context(), created.Cmd[0], created.Cmd[1:]...)
	cmd.Env = append(os.Environ(), created.Env...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Stdout = &stdout

	err := cmd.Run()
	if err != nil {
		require.ErrorAs(t, err, new(*exec.ExitError), "run container command")
	}

	return stdout.String(), cmd.ProcessState.ExitCode()
}

// fakeDockerd is a minimal Docker Engine API for one container. It records
// the container-create request and the bytes sent to the container's stdin.
// Like a process that reads all of its input, the container exits only after
// stdin is closed, when a client is attached to it.
type fakeDockerd struct {
	mu        sync.Mutex
	created   container.Config
	attached  bool
	stdin     []byte
	stdinDone chan struct{}
	isRemoved bool
}

const fakeContainerID = "gozero-test"

var apiVersionPrefix = regexp.MustCompile(`^/v[0-9.]+`)

// newFakeDockerd starts a fakeDockerd and points the Docker client and the
// docker CLI check in sandbox.NewDockerSandbox at it.
func newFakeDockerd(t *testing.T) *fakeDockerd {
	t.Helper()

	dockerd := &fakeDockerd{stdinDone: make(chan struct{})}
	srv := httptest.NewServer(dockerd.handler())
	t.Cleanup(srv.Close)
	t.Setenv("DOCKER_HOST", "tcp://"+srv.Listener.Addr().String())
	t.Setenv("DOCKER_CERT_PATH", "")
	t.Setenv("DOCKER_API_VERSION", "")

	// NewDockerSandbox runs "docker info" before it connects to the API.
	bin := t.TempDir()
	//nolint:gosec // the fake docker CLI must be executable
	err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	require.NoError(t, err)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	return dockerd
}

// handler routes the Docker Engine API requests that the sandbox sends.
func (d *fakeDockerd) handler() http.Handler {
	const containerPath = "/containers/" + fakeContainerID

	mux := http.NewServeMux()
	mux.HandleFunc("/_ping", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Api-Version", client.MaxAPIVersion)
		_, _ = io.WriteString(writer, "OK")
	})
	mux.HandleFunc("GET /images/alpine:3/json", func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, `{"Id":"sha256:gozero-test"}`)
	})
	mux.HandleFunc("POST /containers/create", d.create)
	mux.HandleFunc("POST "+containerPath+"/attach", d.attach)
	mux.HandleFunc("POST "+containerPath+"/start", noContent)
	mux.HandleFunc("POST "+containerPath+"/wait", d.wait)
	// No output: the test runs the command itself.
	mux.HandleFunc("GET "+containerPath+"/logs", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("DELETE "+containerPath, d.remove)

	// The client prefixes request paths with the API version, such as /v1.54.
	return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		req.URL.Path = apiVersionPrefix.ReplaceAllString(req.URL.Path, "")
		req.URL.RawPath = ""
		mux.ServeHTTP(writer, req)
	})
}

// recorded returns the container-create request and the stdin bytes.
func (d *fakeDockerd) recorded() (container.Config, string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.created, string(d.stdin)
}

// removed reports whether the container was removed.
func (d *fakeDockerd) removed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.isRemoved
}

func (d *fakeDockerd) create(writer http.ResponseWriter, req *http.Request) {
	d.mu.Lock()
	err := json.NewDecoder(req.Body).Decode(&d.created)
	d.mu.Unlock()

	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)

		return
	}

	writer.WriteHeader(http.StatusCreated)
	_, _ = io.WriteString(writer, `{"Id":"`+fakeContainerID+`"}`)
}

// attach upgrades the connection to a raw stream and reads the container's
// stdin until the client closes its write side.
func (d *fakeDockerd) attach(writer http.ResponseWriter, _ *http.Request) {
	conn, stream, err := http.NewResponseController(writer).Hijack()
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)

		return
	}

	defer func() { _ = conn.Close() }()

	d.mu.Lock()
	d.attached = true
	d.mu.Unlock()

	_, _ = stream.WriteString("HTTP/1.1 101 UPGRADED\r\n" +
		"Content-Type: application/vnd.docker.raw-stream\r\n" +
		"Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
	_ = stream.Flush()

	stdin, _ := io.ReadAll(stream)

	d.mu.Lock()
	d.stdin = stdin
	d.mu.Unlock()
	close(d.stdinDone)
}

// wait answers when the container exits: at once, or after its stdin is
// closed when a client is attached.
func (d *fakeDockerd) wait(writer http.ResponseWriter, req *http.Request) {
	d.mu.Lock()
	attached := d.attached
	d.mu.Unlock()

	if attached {
		select {
		case <-d.stdinDone:
		case <-req.Context().Done():
			return
		}
	}

	_, _ = io.WriteString(writer, `{"StatusCode":0}`)
}

func (d *fakeDockerd) remove(writer http.ResponseWriter, _ *http.Request) {
	d.mu.Lock()
	d.isRemoved = true
	d.mu.Unlock()

	writer.WriteHeader(http.StatusNoContent)
}

func noContent(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusNoContent)
}

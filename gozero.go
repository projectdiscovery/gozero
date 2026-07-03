package gozero

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/projectdiscovery/gozero/cmdexec"
	"github.com/projectdiscovery/gozero/confine"
	"github.com/projectdiscovery/gozero/types"
)

// Gozero is executor for gozero
type Gozero struct {
	Options  *Options
	confiner confine.Confiner
}

// New creates a new gozero executor.
//
// When Options.Sandbox is set (or Options.Confinement is provided), New builds
// the confinement backend up front and FAILS CLOSED: if the requested backend
// is unavailable, New returns an error instead of a permissive executor, so it
// is impossible to reach Eval and then silently run unconfined.
func New(options *Options) (*Gozero, error) {
	if len(options.Engines) == 0 {
		return nil, ErrNoEngines
	}
	// attempt to locate the interpreter by executing it
	for _, engine := range options.Engines {
		// use lookpath to check if engine is available
		// this ignores path confusion issues where binary with same name exists in current path
		fpath, err := exec.LookPath(engine)
		if err != nil {
			continue
		} else {
			options.engine = fpath
			break
		}
	}
	if options.engine == "" {
		return nil, ErrNoValidEngine
	}

	g := &Gozero{Options: options}
	if options.Sandbox || options.Confinement != nil {
		c, err := confine.New(options.Confinement)
		if err != nil {
			// Fail closed: confinement was requested but cannot be established.
			return nil, fmt.Errorf("gozero: confinement required but unavailable: %w", err)
		}
		g.confiner = c
	}
	return g, nil
}

// Close releases resources held by the executor (e.g. a confinement backend's
// docker client). Safe to call on a nil confiner.
func (g *Gozero) Close() error {
	if g.confiner != nil {
		return g.confiner.Close()
	}
	return nil
}

// Eval evaluates the source code and returns the output
// input = stdin , src = source code , args = arguments
func (g *Gozero) Eval(ctx context.Context, src, input *Source, args ...string) (*types.Result, error) {
	if g.Options.EarlyCloseFileDescriptor {
		_ = src.File.Close()
	}
	// Confined path: every execution goes through the OS-enforced boundary. This
	// is the only place the payload runs when a sandbox was requested — there is
	// no unconfined fallback.
	if g.confiner != nil {
		spec, err := g.buildSpec(src, input, args...)
		if err != nil {
			return nil, err
		}
		return g.confiner.Run(ctx, spec)
	}

	allargs := []string{}
	allargs = append(allargs, g.Options.Args...)
	allargs = append(allargs, src.Filename)
	allargs = append(allargs, args...)
	gcmd, err := cmdexec.NewCommand(g.Options.engine, allargs...)
	if err != nil {
		// returns error if binary(engine) does not exist
		return nil, err
	}
	if g.Options.DebugMode {
		gcmd.EnableDebugMode()
	}
	gcmd.SetStdin(input.File) // stdin
	// add both input and src variables if any
	gcmd.AddVars(src.Variables...) // variables as environment variables
	gcmd.AddVars(input.Variables...)
	return gcmd.Execute(ctx)
}

// buildSpec assembles the confinement Spec for an execution. The source is
// carried as bytes (never interpolated into a shell) and the declared
// interpreter is command[0], so the confiner runs exactly the intended program.
func (g *Gozero) buildSpec(src, input *Source, args ...string) (confine.Spec, error) {
	scriptData, err := src.ReadAll()
	if err != nil {
		return confine.Spec{}, err
	}

	env := make(map[string]string, len(src.Variables)+len(input.Variables))
	for _, v := range src.Variables {
		env[v.Name] = v.Value
	}
	for _, v := range input.Variables {
		env[v.Name] = v.Value
	}

	command := make([]string, 0, len(g.Options.Args)+len(args)+2)
	command = append(command, g.Options.engine)
	command = append(command, g.Options.Args...)
	command = append(command, src.Filename)
	command = append(command, args...)

	return confine.Spec{
		Command:    command,
		ScriptPath: src.Filename,
		ScriptData: scriptData,
		Env:        env,
		Stdin:      input.File,
		Debug:      g.Options.DebugMode,
	}, nil
}

// EvalWithVirtualEnv evaluates the source code in a one-off confinement backend
// described by policy, independently of the executor's own Options.Sandbox
// setting. Use it to pick a backend per call (e.g. force Docker) without
// rebuilding the executor.
//
// It uses the same hardened, fail-closed confiner as Eval: the source is
// injected as bytes (no shell heredoc to break out of) and, if the policy's
// backend cannot be established, execution is refused rather than run
// unconfined. A nil policy uses confine.DefaultPolicy().
func (g *Gozero) EvalWithVirtualEnv(ctx context.Context, policy *confine.Policy, src, input *Source, args ...string) (*types.Result, error) {
	confiner, err := confine.New(policy)
	if err != nil {
		return nil, fmt.Errorf("gozero: confinement required but unavailable: %w", err)
	}
	defer func() { _ = confiner.Close() }()

	spec, err := g.buildSpec(src, input, args...)
	if err != nil {
		return nil, err
	}
	return confiner.Run(ctx, spec)
}

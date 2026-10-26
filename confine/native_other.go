//go:build !linux && !darwin

package confine

// newNativeConfiner has no native mechanism on this OS, so it returns nil and
// New fails closed for BackendAuto/native. Use BackendDocker where a daemon is
// available, or BackendHost to run unconfined deliberately.
func newNativeConfiner(p Policy) Confiner {
	p.Logger.Debug("confine: no native confiner for this OS")
	return nil
}

package confine

import (
	"context"
	"time"
)

// withTimeout wraps ctx with d when d > 0, otherwise returns ctx unchanged with
// a no-op cancel. Lets a Policy.Timeout bound an execution on top of any
// deadline the caller's ctx already carries.
func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}

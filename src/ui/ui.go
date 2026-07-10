// Package ui owns the terminal. It is the only package that writes to the
// user's console, and nothing under src/ may import it — depguard enforces
// that, so a library or server embedding the DAG links no rendering code at
// all and cannot print by accident.
//
// It renders a Docker-pull-style block of live status rows at the bottom of the
// screen. Rows appear when work starts, tick up while it runs, and vanish when
// it finishes. Anything written through the UI (zap's console output, the
// per-package audit lines) erases the rows, prints cleanly, then repaints them
// underneath, so ordinary output and the live rows never collide. That only
// holds because the UI is the sole writer: a stray fmt.Fprintf(os.Stderr, ...)
// would desync the cursor arithmetic.
//
// Work is reported to it as observe spans, not drawn by its callers. The DAG
// says "a fetcher node started"; this package decides that means the phase row
// should now read "(fetching registry metadata)".
//
// When not attached to a terminal (piped, redirected, CI) the rows are
// suppressed and writes pass straight through, so machine output and
// non-interactive behavior are unchanged.
package ui

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/observe"
)

// UI renders live status rows and serializes all console output against them.
// It is safe for concurrent use and also implements io.Writer.
type UI struct {
	w       io.Writer
	enabled bool
	width   int // terminal columns; 0 means "unknown, don't truncate"

	mu      sync.Mutex
	rows    []*row
	painted int // rows currently drawn on screen
	frame   int
	running bool
	ticker  *time.Ticker
	done    chan struct{}
}

// New returns a UI writing to w. When enabled is false the rows are suppressed
// and writes pass straight through; completion lines and log output still
// print, so non-interactive output is unchanged. width is the terminal column
// count used to keep rows from wrapping (0 disables truncation).
func New(w io.Writer, enabled bool, width int) *UI {
	return &UI{w: w, enabled: enabled, width: width}
}

// Reporter returns the observe.Reporter that renders spans as rows. It stays
// live on a disabled UI: rows are suppressed but batch headers and completion
// lines still print, matching non-interactive behavior.
func (u *UI) Reporter() observe.Reporter { return &reporter{ui: u} }

type ctxKey struct{}

// NewContext installs u for retrieval by FromContext, and installs its Reporter
// so domain code reached through ctx reports work without knowing a terminal
// exists. Callers that skip this get a silent, allocation-free no-op.
func NewContext(ctx context.Context, u *UI) context.Context {
	ctx = observe.WithReporter(ctx, u.Reporter())
	return context.WithValue(ctx, ctxKey{}, u)
}

// FromContext returns the UI stored in ctx, or a disabled one writing to
// io.Discard so callers never need a nil check.
//
// The fallback discards rather than falling back to stderr on purpose: code
// reached without a UI installed — the server, tests, library callers — must
// stay silent, not print to whatever fd happens to be open.
func FromContext(ctx context.Context) *UI {
	if u, ok := ctx.Value(ctxKey{}).(*UI); ok && u != nil {
		return u
	}
	return &UI{w: io.Discard}
}

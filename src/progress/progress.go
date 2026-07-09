// Package progress renders a Docker-pull-style block of live status rows to a
// TTY so long-running, concurrent work is visibly alive instead of silent.
//
// Each unit of work is a Task with its own row and its own elapsed timer: rows
// appear when work starts, tick up while it runs, and vanish when it finishes.
// The sequential registry prefetch shows a single growing row; the bounded-
// parallel audit phase shows up to one row per in-flight worker.
//
// The block lives at the bottom of the terminal. Anything written through the
// Display (the zap logger's console output, the per-package audit lines) erases
// the rows, prints cleanly, then repaints the rows underneath, so ordinary
// output and the live rows never collide.
//
// When not attached to a terminal (piped, redirected, CI) the whole thing is a
// no-op: Tasks do nothing and writes pass straight through, so machine output
// and non-interactive behavior are unchanged.
package progress

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap/zapcore"
)

const clearLine = "\r\x1b[K"

var spinner = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}

// Display owns a block of live status rows. It is safe for concurrent use and
// also implements io.Writer: writes are printed above the rows without tearing
// them. The zero-usable form is a disabled no-op.
type Display struct {
	w       io.Writer
	enabled bool
	width   int // terminal columns; 0 means "unknown, don't truncate"

	mu      sync.Mutex
	tasks   []*Task
	painted int // rows currently drawn on screen
	frame   int
	running bool
	ticker  *time.Ticker
	done    chan struct{}
	werr    error // first terminal write error; painting goes quiet after it
}

// Task is a single live row rendered as:
//
//	⠼ <text>  <M:SS>  (<node>)
//
// e.g. "⠼ [1/10] npm/left-pad  3:26  (fetching registry metadata)". node is
// optional. All methods are safe to call from any goroutine and are no-ops on a
// disabled Display.
type Task struct {
	d     *Display
	text  string
	node  string
	start time.Time
	// nodeFirst renders "text (node)  M:SS" instead of "text  M:SS  (node)".
	// Used by phase rows whose node changes over time and reads as the subject.
	nodeFirst bool
}

// New returns a Display writing to w. When enabled is false every Task method is
// a no-op and writes pass straight through to w. width is the terminal column
// count used to keep rows from wrapping (0 disables truncation).
func New(w io.Writer, enabled bool, width int) *Display {
	return &Display{w: w, enabled: enabled, width: width}
}

// Start adds a row showing text (e.g. "[1/10] npm/left-pad") with an optional
// parenthetical node/context (e.g. "fetching registry metadata") and its own
// elapsed timer, rendered "text  M:SS  (node)". Call Task.Done when done.
func (d *Display) Start(text, node string) *Task {
	return d.start(text, node, false)
}

// StartPhase adds a phase row rendered "text  (node)  M:SS" — the node (updated
// via Task.SetNode as work advances) reads as the current activity.
func (d *Display) StartPhase(text string) *Task {
	return d.start(text, "", true)
}

func (d *Display) start(text, node string, nodeFirst bool) *Task {
	t := &Task{d: d, text: text, node: node, nodeFirst: nodeFirst, start: time.Now()}
	if !d.enabled {
		return t
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tasks = append(d.tasks, t)
	d.ensureRunningLocked()
	d.redrawLocked()
	return t
}

// SetNode updates the parenthetical node/context shown on the row, e.g. as a
// phase row advances through the DAG nodes it is running. No-op if unchanged.
func (t *Task) SetNode(node string) {
	if t == nil {
		return
	}
	d := t.d
	if d == nil || !d.enabled {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if t.node == node {
		return
	}
	t.node = node
	d.redrawLocked()
}

// Done removes the row.
func (t *Task) Done() {
	if t == nil {
		return
	}
	d := t.d
	if d == nil || !d.enabled {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, x := range d.tasks {
		if x == t {
			d.tasks = append(d.tasks[:i], d.tasks[i+1:]...)
			break
		}
	}
	d.redrawLocked()
	if len(d.tasks) == 0 {
		d.stopRunningLocked()
	}
}

// Stop clears the whole block and halts the ticker. Safe to call when idle.
func (d *Display) Stop() {
	if !d.enabled {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tasks = nil
	d.eraseLocked()
	d.stopRunningLocked()
}

// Print writes s above the live rows: erase the block, print, repaint. Use it
// for human-facing lines (log output, per-package audit results) that should
// scroll cleanly above the in-flight rows.
func (d *Display) Print(s string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.enabled {
		d.emit(s)
		return
	}
	d.eraseLocked()
	d.emit(s)
	d.redrawLocked()
}

// Write lets a Display act as the zap console sink (io.Writer). A dropped frame
// is not actionable for the logger, so it always reports success.
func (d *Display) Write(p []byte) (int, error) {
	d.Print(string(p))
	return len(p), nil
}

// LogWriter returns a WriteSyncer for the zap console core.
func (d *Display) LogWriter() zapcore.WriteSyncer { return zapcore.AddSync(d) }

// emit writes a raw frame to the terminal. Painting is best-effort: once a
// write fails (closed terminal, broken pipe) the Display goes quiet rather than
// erroring on every subsequent frame.
func (d *Display) emit(s string) {
	if d.werr != nil {
		return
	}
	if _, err := io.WriteString(d.w, s); err != nil {
		d.werr = err
	}
}

func (d *Display) ensureRunningLocked() {
	if d.running {
		return
	}
	d.running = true
	d.done = make(chan struct{})
	d.ticker = time.NewTicker(150 * time.Millisecond)
	go d.run(d.ticker, d.done)
}

func (d *Display) stopRunningLocked() {
	if !d.running {
		return
	}
	d.running = false
	d.ticker.Stop()
	close(d.done)
}

func (d *Display) run(t *time.Ticker, done chan struct{}) {
	for {
		select {
		case <-done:
			return
		case <-t.C:
			d.mu.Lock()
			if d.running {
				d.frame++
				d.redrawLocked()
			}
			d.mu.Unlock()
		}
	}
}

// redrawLocked repaints the block in place: move to its top, rewrite each row,
// then erase any rows left over from a taller previous frame. The whole frame
// is emitted in one write to avoid flicker; the paint is best-effort so a write
// error is intentionally ignored.
func (d *Display) redrawLocked() {
	var b strings.Builder
	if d.painted > 0 {
		b.WriteString(cursorUp(d.painted))
	}
	for _, t := range d.tasks {
		b.WriteString(clearLine + d.renderLocked(t) + "\n")
	}
	if extra := d.painted - len(d.tasks); extra > 0 {
		b.WriteString(strings.Repeat(clearLine+"\n", extra))
		b.WriteString(cursorUp(extra)) // back up so the cursor rests just below the rows
	}
	d.painted = len(d.tasks)
	d.emit(b.String())
}

// eraseLocked wipes the block and leaves the cursor at its top so the next
// write starts where the rows were.
func (d *Display) eraseLocked() {
	if d.painted == 0 {
		return
	}
	up := cursorUp(d.painted)
	d.emit(up + strings.Repeat(clearLine+"\n", d.painted) + up)
	d.painted = 0
}

// cursorUp is the ANSI sequence to move the cursor up n lines.
func cursorUp(n int) string { return "\x1b[" + strconv.Itoa(n) + "A" }

func (d *Display) renderLocked(t *Task) string {
	frame := spinner[d.frame%len(spinner)]
	elapsed := mmss(time.Since(t.start))
	node := ""
	if t.node != "" {
		node = "  (" + t.node + ")"
	}
	var row string
	if t.nodeFirst {
		row = fmt.Sprintf("%c %s%s  %s", frame, t.text, node, elapsed)
	} else {
		row = fmt.Sprintf("%c %s  %s%s", frame, t.text, elapsed, node)
	}
	return truncate(row, d.width)
}

// mmss formats a duration as M:SS (e.g. 3:26).
func mmss(d time.Duration) string {
	s := int(d.Seconds())
	return fmt.Sprintf("%d:%02d", s/60, s%60)
}

// truncate clamps s to width columns (approximating one column per rune) so a
// long row can't wrap and corrupt the cursor math. width <= 0 disables it.
func truncate(s string, width int) string {
	if width <= 0 {
		return s
	}
	r := []rune(s)
	if len(r) <= width {
		return s
	}
	return string(r[:width-1]) + "…"
}

type ctxKey struct{}

// NewContext stores d for retrieval by FromContext.
func NewContext(ctx context.Context, d *Display) context.Context {
	return context.WithValue(ctx, ctxKey{}, d)
}

// FromContext returns the Display stored in ctx, or a disabled no-op Display
// (writing to io.Discard) so callers never need a nil check.
func FromContext(ctx context.Context) *Display {
	if d, ok := ctx.Value(ctxKey{}).(*Display); ok && d != nil {
		return d
	}
	return &Display{w: io.Discard}
}

type taskKey struct{}

// WithTask marks t as the "current phase" task for ctx, so code running under it
// (e.g. the DAG executor) can update its node label via TaskFromContext.
func WithTask(ctx context.Context, t *Task) context.Context {
	return context.WithValue(ctx, taskKey{}, t)
}

// TaskFromContext returns the phase task set by WithTask, or nil. Task methods
// are nil-safe, so callers can use the result without a guard.
func TaskFromContext(ctx context.Context) *Task {
	t, _ := ctx.Value(taskKey{}).(*Task)
	return t
}

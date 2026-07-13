package ui

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const clearLine = "\r\x1b[K"

var spinner = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}

// tickInterval is how often running rows repaint to advance their spinner and
// elapsed timer.
const tickInterval = 150 * time.Millisecond

// row is one live line. Phase rows render "text (activity)  M:SS", where the
// activity is derived from the child node spans currently in flight. Other
// rows render "text  M:SS  (note)" with a fixed note.
//
// All fields are read and written under UI.mu.
type row struct {
	text  string
	start time.Time
	phase bool

	note   string      // fixed parenthetical, for non-phase rows
	active []*liveSpan // in-flight child node spans, for phase rows
	total  int         // sibling count for a counted phase; 0 = no "[ ⠦/N]" prefix
}

// activity is the parenthetical for a row. A phase whose stage is running
// several nodes at once names one of them and counts the rest — the DAG
// executor runs every node in a stage concurrently, so without this the label
// would be whichever goroutine wrote last, flickering on every repaint.
//
// The named node is the lexically smallest rather than the most recent, so the
// row is stable while a stage runs and reproducible under test.
func (rw *row) activity() string {
	if !rw.phase {
		return rw.note
	}
	switch len(rw.active) {
	case 0:
		return ""
	case 1:
		return rw.active[0].label
	}
	first := rw.active[0].label
	for _, s := range rw.active[1:] {
		if s.label < first {
			first = s.label
		}
	}
	return fmt.Sprintf("%s +%d", first, len(rw.active)-1)
}

func (rw *row) dropActive(s *liveSpan) {
	for i, x := range rw.active {
		if x == s {
			rw.active = append(rw.active[:i], rw.active[i+1:]...)
			return
		}
	}
}

// addRowLocked appends rw and starts the ticker if it is not already running.
func (u *UI) addRowLocked(rw *row) {
	u.rows = append(u.rows, rw)
	u.ensureRunningLocked()
	u.redrawLocked()
}

func (u *UI) removeRow(rw *row) {
	if rw == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	for i, x := range u.rows {
		if x == rw {
			u.rows = append(u.rows[:i], u.rows[i+1:]...)
			break
		}
	}
	u.redrawLocked()
	if len(u.rows) == 0 {
		u.stopRunningLocked()
	}
}

// Stop clears the whole block and halts the ticker. Safe to call when idle.
func (u *UI) Stop() {
	if !u.enabled {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.rows = nil
	u.eraseLocked()
	u.stopRunningLocked()
}

func (u *UI) ensureRunningLocked() {
	if u.running {
		return
	}
	u.running = true
	u.done = make(chan struct{})
	u.ticker = time.NewTicker(tickInterval)
	go u.run(u.ticker, u.done)
}

func (u *UI) stopRunningLocked() {
	if !u.running {
		return
	}
	u.running = false
	u.ticker.Stop()
	close(u.done)
}

// run repaints on every tick. The ticker and done channel are passed in rather
// than read from u, so a Stop/restart cycle cannot leave this goroutine driving
// a newer generation's ticker.
func (u *UI) run(t *time.Ticker, done chan struct{}) {
	for {
		select {
		case <-done:
			return
		case <-t.C:
			u.mu.Lock()
			if u.running {
				u.frame++
				u.redrawLocked()
			}
			u.mu.Unlock()
		}
	}
}

// redrawLocked repaints the block in place: move to its top, rewrite each row,
// then erase any rows left over from a taller previous frame. The whole frame
// is emitted in one write to avoid flicker, and leaves the cursor resting just
// below the rows.
func (u *UI) redrawLocked() {
	if !u.enabled {
		return
	}
	var b strings.Builder
	if u.painted > 0 {
		b.WriteString(cursorUp(u.painted))
	}
	for _, rw := range u.rows {
		b.WriteString(clearLine + u.renderLocked(rw) + "\n")
	}
	if extra := u.painted - len(u.rows); extra > 0 {
		b.WriteString(strings.Repeat(clearLine+"\n", extra))
		b.WriteString(cursorUp(extra)) // back up so the cursor rests just below the rows
	}
	u.painted = len(u.rows)
	u.paint(b.String())
}

// eraseLocked wipes the block and leaves the cursor at its top so the next
// write starts where the rows were.
func (u *UI) eraseLocked() {
	if u.painted == 0 {
		return
	}
	up := cursorUp(u.painted)
	u.paint(up + strings.Repeat(clearLine+"\n", u.painted) + up)
	u.painted = 0
}

// cursorUp is the ANSI sequence to move the cursor up n lines.
func cursorUp(n int) string { return "\x1b[" + strconv.Itoa(n) + "A" }

func (u *UI) renderLocked(rw *row) string {
	frame := spinner[u.frame%len(spinner)]
	elapsed := mmss(time.Since(rw.start))
	note := rw.activity()
	if note != "" {
		note = "  (" + note + ")"
	}
	var s string
	switch {
	case rw.phase && rw.total > 0:
		// A counted phase leads with the same aligned "[  ⠦/N]" prefix the
		// finished lines print as "[  8/N]", so in-flight and completed rows
		// share one column. The spinner stands in for this row's number.
		s = fmt.Sprintf("%s %s%s  %s", counterPrefix(frame, rw.total), rw.text, note, elapsed)
	case rw.phase:
		s = fmt.Sprintf("%c %s%s  %s", frame, rw.text, note, elapsed)
	default:
		s = fmt.Sprintf("%c %s  %s%s", frame, rw.text, elapsed, note)
	}
	return truncate(s, u.width)
}

// counterPrefix renders "[  ⠦/N]" with the spinner right-aligned to total's
// digit width, matching printProgress's "[%*d/%d]" so a running row and the
// completed line it becomes occupy the same column. The spinner is a single
// display column, so it takes the place of one digit.
func counterPrefix(frame rune, total int) string {
	pad := strings.Repeat(" ", len(strconv.Itoa(total))-1)
	return fmt.Sprintf("[%s%c/%d]", pad, frame, total)
}

// mmss formats a duration as M:SS (e.g. 3:26).
func mmss(d time.Duration) string {
	s := int(d.Seconds())
	return fmt.Sprintf("%d:%02d", s/60, s%60)
}

// truncate clamps s to width-1 columns so a long row can't wrap and corrupt the
// cursor math. A row that fills the final column leaves the terminal in a
// deferred-wrap state, and the "\n" that follows it then costs an extra line —
// hence width-1 rather than width. width <= 0 disables truncation.
//
// One column per rune is an approximation: the wide glyphs rendered here (the
// braille spinner, "…", "✗") are single-column in most terminals, but CJK
// package names will under-count.
func truncate(s string, width int) string {
	if width <= 0 {
		return s
	}
	if width == 1 {
		return ""
	}
	r := []rune(s)
	if len(r) < width {
		return s
	}
	return string(r[:width-2]) + "…"
}

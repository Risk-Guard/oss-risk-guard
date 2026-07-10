package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// The cursor arithmetic is the whole risk surface of this package, and asserting
// on substrings ("does the output mention npm/left-pad?") cannot see a
// regression in it. These tests pin the exact bytes.
//
// They drive redrawLocked/eraseLocked directly rather than through startRow, so
// no ticker goroutine runs and frame stays 0 — the spinner is always '⠋' and the
// output is reproducible.

func goldenUI() (*UI, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return &UI{w: buf, enabled: true}, buf
}

func (u *UI) redrawForTest() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.redrawLocked()
}

func (u *UI) eraseForTest() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.eraseLocked()
}

func fixedRow(text string, phase bool) *row {
	return &row{text: text, start: time.Now(), phase: phase}
}

func check(t *testing.T, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("frame bytes mismatch\n got: %q\nwant: %q", got, want)
	}
}

// The first paint has nothing on screen to move up over.
func TestGoldenFirstPaintDoesNotMoveCursor(t *testing.T) {
	u, buf := goldenUI()
	u.rows = []*row{fixedRow("alpha", false)}
	u.redrawForTest()

	check(t, buf.String(), clearLine+"⠋ alpha  0:00"+"\n")
	if u.painted != 1 {
		t.Fatalf("painted = %d, want 1", u.painted)
	}
}

// A repaint rewinds exactly as many lines as it previously drew.
func TestGoldenRepaintRewindsPaintedLines(t *testing.T) {
	u, buf := goldenUI()
	u.rows = []*row{fixedRow("alpha", false)}
	u.redrawForTest()
	buf.Reset()

	u.rows = append(u.rows, fixedRow("beta", false))
	u.redrawForTest()

	want := cursorUp(1) +
		clearLine + "⠋ alpha  0:00" + "\n" +
		clearLine + "⠋ beta  0:00" + "\n"
	check(t, buf.String(), want)
	if u.painted != 2 {
		t.Fatalf("painted = %d, want 2", u.painted)
	}
}

// Shrinking the block must clear the orphaned line and back the cursor up over
// it, or the next frame's cursorUp count is off by the difference.
func TestGoldenShrinkClearsOrphanedRow(t *testing.T) {
	u, buf := goldenUI()
	u.rows = []*row{fixedRow("alpha", false), fixedRow("beta", false)}
	u.redrawForTest()
	buf.Reset()

	u.rows = u.rows[:1]
	u.redrawForTest()

	want := cursorUp(2) +
		clearLine + "⠋ alpha  0:00" + "\n" +
		clearLine + "\n" + // wipe the line beta occupied
		cursorUp(1) // rest just below the surviving row
	check(t, buf.String(), want)
	if u.painted != 1 {
		t.Fatalf("painted = %d, want 1", u.painted)
	}
}

// erase leaves the cursor at the top of the block so the next write lands where
// the rows were, and forgets what was painted.
func TestGoldenEraseReturnsToBlockTop(t *testing.T) {
	u, buf := goldenUI()
	u.rows = []*row{fixedRow("alpha", false), fixedRow("beta", false)}
	u.redrawForTest()
	buf.Reset()

	u.eraseForTest()

	want := cursorUp(2) + clearLine + "\n" + clearLine + "\n" + cursorUp(2)
	check(t, buf.String(), want)
	if u.painted != 0 {
		t.Fatalf("painted = %d after erase, want 0", u.painted)
	}
}

// Erasing an empty block must emit nothing. cursorUp(0) is not a no-op escape —
// "\x1b[0A" still moves up one line on many terminals.
func TestGoldenEraseWhenNothingPaintedEmitsNothing(t *testing.T) {
	u, buf := goldenUI()
	u.eraseForTest()
	check(t, buf.String(), "")
}

// The erase → print → repaint ordering is what keeps a log line from landing in
// the middle of the row block. This is the sequence that was previously untested.
func TestGoldenPrintErasesThenRepaints(t *testing.T) {
	u, buf := goldenUI()
	u.rows = []*row{fixedRow("alpha", false)}
	u.redrawForTest()
	buf.Reset()

	if err := u.print("a log line\n"); err != nil {
		t.Fatalf("print: %v", err)
	}

	want := cursorUp(1) + clearLine + "\n" + cursorUp(1) + // erase the block
		"a log line\n" + // the line, at the block's old top
		clearLine + "⠋ alpha  0:00" + "\n" // repaint underneath
	check(t, buf.String(), want)
}

// A phase row names its activity before the timer; other rows after it.
func TestGoldenRowLayouts(t *testing.T) {
	u, buf := goldenUI()
	phase := fixedRow("scoring local source", true)
	phase.active = []*liveSpan{{label: "reading git history"}}
	pkg := fixedRow("npm/left-pad", false)
	pkg.note = "fetching registry metadata"
	u.rows = []*row{phase, pkg}
	u.redrawForTest()

	out := buf.String()
	if !strings.Contains(out, "⠋ scoring local source  (reading git history)  0:00") {
		t.Errorf("phase row should read text (activity) timer: %q", out)
	}
	if !strings.Contains(out, "⠋ npm/left-pad  0:00  (fetching registry metadata)") {
		t.Errorf("package row should read text timer (note): %q", out)
	}
}

// A row with no activity renders no empty parentheses.
func TestGoldenEmptyActivityOmitsParens(t *testing.T) {
	u, buf := goldenUI()
	u.rows = []*row{fixedRow("alpha", true)}
	u.redrawForTest()
	if strings.Contains(buf.String(), "(") {
		t.Fatalf("empty activity should not render parens: %q", buf.String())
	}
}

// Rows are clamped short of the final column: filling it leaves the terminal in
// a deferred-wrap state, and the trailing "\n" then costs an extra line, which
// silently desyncs every subsequent cursorUp.
func TestTruncateLeavesFinalColumnFree(t *testing.T) {
	const width = 8
	for _, s := range []string{"abcdefg", "abcdefgh", "abcdefghijklmnop"} {
		if n := len([]rune(truncate(s, width))); n >= width {
			t.Errorf("truncate(%q, %d) = %d runes, want < %d", s, width, n, width)
		}
	}
	if got := truncate("hello", 1); got != "" {
		t.Errorf("width 1 leaves no room for content, got %q", got)
	}
	if got := truncate("hello world", 0); got != "hello world" {
		t.Errorf("width 0 disables truncation, got %q", got)
	}
	if got := truncate("hello", 100); got != "hello" {
		t.Errorf("wide enough should not truncate, got %q", got)
	}
	if got := truncate("hello world", 5); got != "hel…" {
		t.Errorf("truncate to width 5 = %q, want %q", got, "hel…")
	}
}

func TestMMSS(t *testing.T) {
	cases := map[time.Duration]string{
		0:                                "0:00",
		3 * time.Second:                  "0:03",
		59 * time.Second:                 "0:59",
		90 * time.Second:                 "1:30",
		(3*time.Minute + 26*time.Second): "3:26",
		(12*time.Minute + 5*time.Second): "12:05",
	}
	for d, want := range cases {
		if got := mmss(d); got != want {
			t.Errorf("mmss(%v) = %q, want %q", d, got, want)
		}
	}
}

// A disabled UI paints nothing at all, but still passes writes through.
func TestDisabledPaintsNothingButWritesThrough(t *testing.T) {
	var buf bytes.Buffer
	u := New(&buf, false, 0)

	u.rows = []*row{fixedRow("alpha", false)}
	u.redrawForTest()
	if buf.Len() != 0 {
		t.Fatalf("disabled UI painted rows: %q", buf.String())
	}

	u.Printf("hello\n")
	if got := buf.String(); got != "hello\n" {
		t.Fatalf("passthrough = %q, want %q", got, "hello\n")
	}
}

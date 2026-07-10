package ui

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// errWriter fails every write.
type errWriter struct{ err error }

func (w errWriter) Write([]byte) (int, error) { return 0, w.err }

// flakyWriter fails the first n writes, then succeeds.
type flakyWriter struct {
	fails int
	buf   bytes.Buffer
}

func (w *flakyWriter) Write(p []byte) (int, error) {
	if w.fails > 0 {
		w.fails--
		return 0, errors.New("transient")
	}
	return w.buf.Write(p)
}

// shortWriter accepts one byte at a time, as a pipe under pressure may.
type shortWriter struct{ buf bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return w.buf.Write(p[:1])
}

// zap must learn that a log line was lost. Write previously reported success
// unconditionally, so console output could vanish with nothing to show for it.
func TestWriteReportsError(t *testing.T) {
	want := errors.New("broken pipe")
	u := New(errWriter{err: want}, false, 0)

	n, err := u.Write([]byte("a log line\n"))
	if !errors.Is(err, want) {
		t.Fatalf("Write err = %v, want %v", err, want)
	}
	if n != 0 {
		t.Fatalf("Write n = %d on failure, want 0", n)
	}
}

// A single failed write must not permanently silence the UI. In non-interactive
// mode print is the only sink for log lines and audit results, so latching the
// first error would discard the rest of the run's output — precisely in CI,
// where that output is all anyone has.
func TestWriteErrorDoesNotLatch(t *testing.T) {
	w := &flakyWriter{fails: 1}
	u := New(w, false, 0)

	if _, err := u.Write([]byte("first\n")); err == nil {
		t.Fatal("expected the first write to fail")
	}
	if _, err := u.Write([]byte("second\n")); err != nil {
		t.Fatalf("second write should succeed after a transient failure: %v", err)
	}
	if got := w.buf.String(); got != "second\n" {
		t.Fatalf("output after recovery = %q, want %q", got, "second\n")
	}
}

// io.WriteString does not loop, so emit must complete short writes itself or
// the tail of every line is silently dropped.
func TestEmitCompletesShortWrites(t *testing.T) {
	w := &shortWriter{}
	u := New(w, false, 0)

	const line = "a whole log line\n"
	if _, err := u.Write([]byte(line)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := w.buf.String(); got != line {
		t.Fatalf("short writes were not completed: got %q, want %q", got, line)
	}
}

// A failed frame is dropped, not latched: painting is best-effort because the
// next tick redraws the same state anyway.
func TestPaintErrorIsDroppedNotLatched(t *testing.T) {
	w := &flakyWriter{fails: 1}
	u := &UI{w: w, enabled: true}

	u.rows = []*row{fixedRow("alpha", false)}
	u.redrawForTest() // this frame is lost
	u.redrawForTest() // the next one must still paint

	if !strings.Contains(w.buf.String(), "alpha") {
		t.Fatalf("painting stopped after one failed frame: %q", w.buf.String())
	}
}

// Printf keeps a log line intact rather than interleaving it with row repaints.
func TestPrintfKeepsLineIntact(t *testing.T) {
	buf := &syncBuf{}
	u := New(buf, true, 0)
	defer u.Stop()

	u.mu.Lock()
	u.rows = []*row{fixedRow("alpha", false)}
	u.mu.Unlock()

	u.Printf("%s ok\n", "npm/left-pad")
	if !strings.Contains(buf.String(), "npm/left-pad ok\n") {
		t.Fatalf("log line missing or torn: %q", buf.String())
	}
}

// FromContext must never hand back a printer aimed at a real fd. Code reached
// without a UI installed — the server, tests, library callers — stays silent.
func TestFromContextDefaultsToSilentDiscard(t *testing.T) {
	u := FromContext(t.Context())
	if u == nil {
		t.Fatal("FromContext returned nil")
	}
	if u.enabled {
		t.Fatal("default UI should not paint rows")
	}
	u.Printf("this must go nowhere\n")
	if _, err := u.Write([]byte("nor this")); err != nil {
		t.Fatalf("Write on the discard UI: %v", err)
	}
	u.Stop()
}

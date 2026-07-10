package ui

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/observe"
)

// syncBuf is concurrency-safe: an enabled UI runs a ticker goroutine that
// repaints while the test reads.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (u *UI) renderRow(rw *row) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.renderLocked(rw)
}

func rowOf(s observe.Span) *row { return s.(*liveSpan).row }

// The DAG runs every node in a stage concurrently against one phase context.
// Previously each node overwrote the phase label, so the row showed whichever
// goroutine wrote last. Now the row names one node and counts the rest.
func TestPhaseRowNamesOneNodeAndCountsTheRest(t *testing.T) {
	u := New(&syncBuf{}, true, 0)
	defer u.Stop()
	r := u.Reporter()

	pctx, phase := r.Begin(context.Background(), observe.Event{
		Kind: observe.KindPhase, Name: "scoring local source",
	})
	prow := rowOf(phase)

	// Siblings all derive from the same phase context, as the stage loop does.
	_, git := r.Begin(pctx, observe.Event{Kind: "fetch", Type: "*git_clone_metadata.Node"})
	_, fetch := r.Begin(pctx, observe.Event{Kind: "fetch", Type: "*fetcher.Node"})
	_, lic := r.Begin(pctx, observe.Event{Kind: "scan", Type: "*license_files.Node"})

	// Lexically smallest label wins, so the row is stable regardless of the
	// order the goroutines happened to start in.
	if got := u.renderRow(prow); !strings.Contains(got, "(fetching registry metadata +2)") {
		t.Fatalf("row = %q, want the lexically first label and a +2 count", got)
	}

	fetch.End(observe.StatusOK, nil)
	if got := u.renderRow(prow); !strings.Contains(got, "(reading git history +1)") {
		t.Fatalf("row = %q, want the next label and a +1 count", got)
	}

	lic.End(observe.StatusOK, nil)
	if got := u.renderRow(prow); !strings.Contains(got, "(reading git history)") {
		t.Fatalf("row = %q, want a bare label with one node left", got)
	}
	if strings.Contains(u.renderRow(prow), "+") {
		t.Fatalf("a single active node should carry no count: %q", u.renderRow(prow))
	}

	git.End(observe.StatusOK, nil)
	if got := u.renderRow(prow); strings.Contains(got, "(") {
		t.Fatalf("idle phase row should have no parenthetical: %q", got)
	}
}

// A node span reaches past intervening non-phase spans to find its phase row.
func TestNodeSpanFindsEnclosingPhaseThroughBatch(t *testing.T) {
	u := New(&syncBuf{}, true, 0)
	defer u.Stop()
	r := u.Reporter()

	pctx, phase := r.Begin(context.Background(), observe.Event{Kind: observe.KindPhase, Name: "audit"})
	bctx, _ := r.Begin(pctx, observe.Event{Kind: observe.KindBatch, Name: "registry metadata", Total: 4})
	_, node := r.Begin(bctx, observe.Event{Kind: "fetch", Type: "*fetcher.Node"})

	if node.(*liveSpan).prow != rowOf(phase) {
		t.Fatal("node span should annotate the enclosing phase row")
	}
}

// A node running outside any phase must not panic or open a row of its own.
func TestNodeSpanWithoutPhaseIsHarmless(t *testing.T) {
	u := New(&syncBuf{}, true, 0)
	defer u.Stop()
	r := u.Reporter()

	_, node := r.Begin(context.Background(), observe.Event{Kind: "fetch", Type: "*fetcher.Node"})
	node.End(observe.StatusOK, nil)

	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.rows) != 0 {
		t.Fatalf("a phaseless node opened %d rows, want 0", len(u.rows))
	}
}

// One component owns the row and the completion line, so their counters agree.
// Previously rows numbered by start order and completion lines by finish order,
// so "[3/12]" on screen bore no relation to "(7/12)" in the log.
func TestBatchCompletionLinesCountInFinishOrder(t *testing.T) {
	buf := &syncBuf{}
	u := New(buf, false, 0) // non-interactive: lines only, no rows
	r := u.Reporter()

	bctx, batch := r.Begin(context.Background(), observe.Event{
		Kind: observe.KindBatch, Name: "registry metadata", Total: 3,
	})

	for _, name := range []string{"npm/a", "npm/b", "npm/c"} {
		_, s := r.Begin(bctx, observe.Event{Kind: observe.KindPackage, Name: name})
		if name == "npm/b" {
			s.End(observe.StatusError, errors.New("registry 500"))
			continue
		}
		s.End(observe.StatusOK, nil)
	}
	batch.End(observe.StatusOK, nil)

	want := "Fetching registry metadata for 3 packages…\n" +
		"✓ npm/a  (1/3)\n" +
		"✗ npm/b  (2/3)\n" +
		"✓ npm/c  (3/3)\n"
	if got := buf.String(); got != want {
		t.Fatalf("batch output\n got: %q\nwant: %q", got, want)
	}
}

// A single-package fetch is not worth announcing: no header, no rows, no
// completion lines. This rule used to live in the fetcher as `showProgress`.
func TestBatchOfOneIsSilent(t *testing.T) {
	buf := &syncBuf{}
	u := New(buf, false, 0)
	r := u.Reporter()

	bctx, batch := r.Begin(context.Background(), observe.Event{
		Kind: observe.KindBatch, Name: "registry metadata", Total: 1,
	})
	_, s := r.Begin(bctx, observe.Event{Kind: observe.KindPackage, Name: "npm/only"})
	s.End(observe.StatusOK, nil)
	batch.End(observe.StatusOK, nil)

	if got := buf.String(); got != "" {
		t.Fatalf("a batch of one printed %q, want nothing", got)
	}
}

// A package span with no enclosing batch has no counter to report into, and
// must not panic or print a nonsense "(1/0)".
func TestPackageSpanWithoutBatchIsSilent(t *testing.T) {
	buf := &syncBuf{}
	u := New(buf, false, 0)
	r := u.Reporter()

	_, s := r.Begin(context.Background(), observe.Event{Kind: observe.KindPackage, Name: "npm/orphan"})
	s.End(observe.StatusOK, nil)

	if got := buf.String(); got != "" {
		t.Fatalf("orphan package printed %q, want nothing", got)
	}
}

// Rows come and go; the block must be empty once every span has ended.
func TestRowsAreRetiredOnEnd(t *testing.T) {
	u := New(&syncBuf{}, true, 0)
	defer u.Stop()
	r := u.Reporter()

	pctx, phase := r.Begin(context.Background(), observe.Event{Kind: observe.KindPhase, Name: "p"})
	bctx, batch := r.Begin(pctx, observe.Event{Kind: observe.KindBatch, Name: "registry metadata", Total: 2})
	_, a := r.Begin(bctx, observe.Event{Kind: observe.KindPackage, Name: "npm/a"})
	_, b := r.Begin(bctx, observe.Event{Kind: observe.KindPackage, Name: "npm/b"})

	u.mu.Lock()
	n := len(u.rows) // one phase row + two package rows
	u.mu.Unlock()
	if n != 3 {
		t.Fatalf("rows = %d, want 3", n)
	}

	a.End(observe.StatusOK, nil)
	b.End(observe.StatusOK, nil)
	batch.End(observe.StatusOK, nil)
	phase.End(observe.StatusOK, nil)

	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.rows) != 0 {
		t.Fatalf("rows = %d after all spans ended, want 0", len(u.rows))
	}
	if u.running {
		t.Fatal("ticker still running with no rows")
	}
}

// Concurrent spans and writes must not race or tear a completion line.
func TestConcurrentSpansAndWritesDoNotRace(t *testing.T) {
	buf := &syncBuf{}
	u := New(buf, true, 80)
	defer u.Stop()
	r := u.Reporter()

	pctx, phase := r.Begin(context.Background(), observe.Event{Kind: observe.KindPhase, Name: "p"})
	bctx, batch := r.Begin(pctx, observe.Event{Kind: observe.KindBatch, Name: "registry metadata", Total: 12})

	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, s := r.Begin(bctx, observe.Event{Kind: observe.KindPackage, Name: "npm/pkg"})
			_, node := r.Begin(pctx, observe.Event{Kind: "fetch", Type: "*fetcher.Node"})
			node.End(observe.StatusOK, nil)
			s.End(observe.StatusOK, nil)
		}(i)
	}
	wg.Wait()
	batch.End(observe.StatusOK, nil)
	phase.End(observe.StatusOK, nil)

	// Every package reported exactly once, and the counter reached 12.
	out := buf.String()
	if n := strings.Count(out, "✓ npm/pkg"); n != 12 {
		t.Fatalf("counted %d completion lines, want 12", n)
	}
	if !strings.Contains(out, "(12/12)") {
		t.Fatalf("final completion line missing from %q", out)
	}
}

func TestNodeDisplayName(t *testing.T) {
	cases := map[string]string{
		"*fetcher.Node":            "fetching registry metadata",
		"*git_clone_metadata.Node": "reading git history",
		"fetcher.Node":             "fetching registry metadata",
		"*some_new_node.Node":      "some new node", // unlisted: humanized fallback
		"weird":                    "weird",
	}
	for in, want := range cases {
		if got := nodeDisplayName(in); got != want {
			t.Errorf("nodeDisplayName(%q) = %q, want %q", in, got, want)
		}
	}
}

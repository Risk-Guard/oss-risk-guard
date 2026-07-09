package progress

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuf is a concurrency-safe buffer for asserting against interleaved writes
// from the ticker goroutine and task updates.
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

func TestDisabledIsNoOp(t *testing.T) {
	var buf bytes.Buffer
	d := New(&buf, false, 0)

	task := d.Start("[1/3] npm/left-pad", "fetching registry metadata")
	task.Done()
	d.Stop()
	if buf.Len() != 0 {
		t.Fatalf("disabled Display wrote status output: %q", buf.String())
	}

	if _, err := d.Write([]byte("hello\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := buf.String(); got != "hello\n" {
		t.Fatalf("passthrough = %q, want %q", got, "hello\n")
	}
}

func TestRowFormat(t *testing.T) {
	buf := &syncBuf{}
	d := New(buf, true, 0)

	task := d.Start("[1/10] npm/left-pad", "fetching registry metadata")
	task.Done()
	d.Stop()

	out := buf.String()
	// The row must read "[1/10] npm/left-pad  0:00  (fetching registry metadata)".
	if !strings.Contains(out, "[1/10] npm/left-pad") {
		t.Fatalf("output missing package text: %q", out)
	}
	if !strings.Contains(out, "0:00") {
		t.Fatalf("output missing M:SS timer: %q", out)
	}
	if !strings.Contains(out, "(fetching registry metadata)") {
		t.Fatalf("output missing parenthetical node: %q", out)
	}
}

func TestSetNodeUpdatesParenthetical(t *testing.T) {
	buf := &syncBuf{}
	d := New(buf, true, 0)
	task := d.Start("scoring local source", "")
	task.SetNode("fetching registry metadata")
	task.Done()
	d.Stop()
	out := buf.String()
	if !strings.Contains(out, "scoring local source") || !strings.Contains(out, "(fetching registry metadata)") {
		t.Fatalf("SetNode did not render node: %q", out)
	}
}

func TestNilTaskMethodsAreSafe(t *testing.T) {
	var task *Task // e.g. TaskFromContext returned nil
	task.SetNode("x")
	task.Done()
}

func TestRowWithoutNodeOmitsParens(t *testing.T) {
	buf := &syncBuf{}
	d := New(buf, true, 0)
	task := d.Start("scoring local source", "")
	task.Done()
	d.Stop()
	if strings.Contains(buf.String(), "(") {
		t.Fatalf("empty node should not render parens: %q", buf.String())
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

func TestConcurrentTasksAndWritesDoNotRace(t *testing.T) {
	buf := &syncBuf{}
	d := New(buf, true, 80)

	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			task := d.Start("[x/12] npm/pkg", "fetching registry metadata")
			// A completion line locked in above the rows, as the fetcher does.
			_, _ = d.Write([]byte("✓ npm/pkg  (1/12)\n"))
			task.Done()
		}(i)
	}
	wg.Wait()
	d.Stop()

	if strings.Count(buf.String(), "✓ npm/pkg  (1/12)\n") == 0 {
		t.Fatalf("completion line missing from output: %q", buf.String())
	}
}

func TestWriteKeepsLogLineIntact(t *testing.T) {
	buf := &syncBuf{}
	d := New(buf, true, 0)

	task := d.Start("[1/3] npm/left-pad", "fetching registry metadata")
	if _, err := d.Write([]byte("[1/3] npm/left-pad  ok\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	task.Done()
	d.Stop()

	if !strings.Contains(buf.String(), "[1/3] npm/left-pad  ok\n") {
		t.Fatalf("log line missing or torn: %q", buf.String())
	}
}

func TestFromContextDefaultsToNoOp(t *testing.T) {
	d := FromContext(t.Context())
	if d == nil {
		t.Fatal("FromContext returned nil")
	}
	if d.enabled {
		t.Fatal("default Display should be disabled")
	}
	task := d.Start("x", "y")
	task.Done()
	if _, err := d.Write([]byte("z")); err != nil {
		t.Fatalf("Write on no-op Display: %v", err)
	}
	d.Stop()
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello world", 0); got != "hello world" {
		t.Fatalf("width 0 should not truncate: %q", got)
	}
	if got := truncate("hello world", 100); got != "hello world" {
		t.Fatalf("wide enough should not truncate: %q", got)
	}
	got := truncate("hello world", 5)
	if []rune(got)[4] != '…' || len([]rune(got)) != 5 {
		t.Fatalf("truncate to 5 = %q, want 5 runes ending in …", got)
	}
}

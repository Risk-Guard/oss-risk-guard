package observe

import (
	"context"
	"errors"
	"testing"
)

func TestFromUnseededReturnsNop(t *testing.T) {
	if got := From(context.Background()); got != Nop {
		t.Fatalf("From(background) = %#v, want Nop", got)
	}
}

func TestFromNeverReturnsNil(t *testing.T) {
	// A nil Reporter stored under the key must not defeat the fallback.
	ctx := context.WithValue(context.Background(), reporterKey{}, Reporter(nil))
	if From(ctx) != Nop {
		t.Fatal("From must fall back to Nop when the stored Reporter is nil")
	}
	if WithReporter(context.Background(), nil) != context.Background() {
		t.Fatal("WithReporter(nil) should leave ctx unchanged")
	}
}

func TestWithReporterRoundTrips(t *testing.T) {
	r := &recorder{}
	ctx := WithReporter(context.Background(), r)
	if From(ctx) != Reporter(r) {
		t.Fatal("From did not return the installed Reporter")
	}
}

// The whole design rests on this: a server or library that never installs a
// Reporter pays nothing per DAG node. nopSpan is zero-size, so boxing it into
// the Span interface points at runtime.zerobase, and Nop.Begin returns ctx
// unwrapped rather than allocating a context.valueCtx.
func TestNopBeginEndDoesNotAllocate(t *testing.T) {
	ctx := context.Background()
	ev := Event{Kind: "fetch", Type: "*fetcher.Node"}

	allocs := testing.AllocsPerRun(1000, func() {
		c, span := Nop.Begin(ctx, ev)
		span.End(StatusOK, nil)
		_ = c
	})
	if allocs != 0 {
		t.Fatalf("Nop Begin/End allocated %v objects per run, want 0", allocs)
	}
}

func TestNopBeginReturnsSameContext(t *testing.T) {
	ctx := context.Background()
	got, _ := Nop.Begin(ctx, Event{})
	if got != ctx {
		t.Fatal("Nop.Begin must return the context unwrapped")
	}
}

// This is the property the DAG executor relies on. Its stage goroutines all
// call Begin with the same stage context; each must get an independent span
// that resolves to the shared phase as its parent, and none may disturb the
// context the siblings are still reading.
func TestBeginNestsWithoutMutatingParent(t *testing.T) {
	r := &recorder{}
	root := WithReporter(context.Background(), r)

	phaseCtx, phase := r.Begin(root, Event{Kind: KindPhase, Name: "scoring local source"})

	aCtx, aSpan := r.Begin(phaseCtx, Event{Kind: "fetch"})
	bCtx, bSpan := r.Begin(phaseCtx, Event{Kind: "check"})

	if aSpan.(*recSpan).parent != phase || bSpan.(*recSpan).parent != phase {
		t.Fatal("children should resolve the phase span as their parent")
	}
	if aSpan == bSpan {
		t.Fatal("siblings must get independent spans")
	}
	if aCtx == bCtx {
		t.Fatal("siblings must derive independent contexts")
	}
	// The parent context still resolves to the phase, not to either child.
	if spanIn(phaseCtx) != phase {
		t.Fatal("deriving children must not mutate the parent context")
	}
}

func TestSpanEndCarriesStatusAndError(t *testing.T) {
	r := &recorder{}
	_, span := r.Begin(context.Background(), Event{Kind: KindPackage, Name: "npm/left-pad"})
	want := errors.New("registry 500")
	span.End(StatusError, want)

	if len(r.ended) != 1 {
		t.Fatalf("ended = %d spans, want 1", len(r.ended))
	}
	if r.ended[0].status != StatusError || !errors.Is(r.ended[0].err, want) {
		t.Fatalf("End recorded (%v, %v), want (%v, %v)", r.ended[0].status, r.ended[0].err, StatusError, want)
	}
}

// recorder is a minimal Reporter, standing in for what src/ui implements. That
// this fits in a dozen lines is the argument for the interface staying small.
type recorder struct {
	ended []ending
}

type ending struct {
	status Status
	err    error
}

type recSpan struct {
	r      *recorder
	ev     Event
	parent Span
}

type recKey struct{}

func (r *recorder) Begin(ctx context.Context, ev Event) (context.Context, Span) {
	s := &recSpan{r: r, ev: ev, parent: spanIn(ctx)}
	return context.WithValue(ctx, recKey{}, s), s
}

func (s *recSpan) End(status Status, err error) {
	s.r.ended = append(s.r.ended, ending{status: status, err: err})
}

// spanIn returns the innermost span in ctx, or nil. Returning the typed nil as
// a Span interface would make it non-nil, hence the explicit guard.
func spanIn(ctx context.Context) Span {
	s, _ := ctx.Value(recKey{}).(*recSpan)
	if s == nil {
		return nil
	}
	return s
}

// Package observe is the seam between code that does work and code that shows
// work happening. A package doing work reports what it is doing; something
// else — a terminal renderer, or nothing at all — decides what that looks like.
//
// The package deliberately has no io.Writer, no logger, and no os.Stderr: there
// is nothing here that can print. That is the point. Domain packages depend on
// observe, never on a renderer, so a library or server embedding them stays
// silent because the rendering code is not linked, not because a flag is off.
//
// A Reporter absent from the context resolves to Nop, whose Begin/End pair
// allocates nothing. Non-interactive callers pay an interface call.
//
// Scope: this drives a live progress display for humans at a terminal. It is
// not telemetry. Machine-readable node timing already goes to the structured
// log. Keep the interface at Begin and End — no attributes, no links, no
// subscribers — or it becomes a second, worse logging system.
package observe

import "context"

// Status is the terminal state of a Span.
type Status string

const (
	StatusOK      Status = "ok"
	StatusSkipped Status = "skipped"
	StatusError   Status = "error"
)

// Event kinds. Anything else is treated as a DAG node running inside a phase,
// which lets Event.Kind carry the node's own kind ("fetch", "check", …).
const (
	// KindPhase is a top-level unit of work with its own row, e.g. scoring one
	// package or the local source tree. Nodes beginning under a phase update
	// that phase's row rather than opening rows of their own.
	KindPhase = "phase"
	// KindBatch is a group of sibling KindPackage spans whose size is known up
	// front, e.g. a bulk registry prefetch. Total says how many.
	KindBatch = "batch"
	// KindPackage is one member of a batch.
	KindPackage = "package"
)

// Event describes work about to start.
type Event struct {
	// Kind is KindPhase, KindBatch, KindPackage, or a DAG node's kind.
	Kind string
	// Type is the node's Go type, e.g. "*fetcher.Node". Renderers map it to
	// human copy; the domain does not know what that copy says.
	Type string
	// Name is the subject: a phase title or a package key. Empty for nodes.
	Name string
	// Total is the member count of a KindBatch, and zero elsewhere. It is a
	// fact about the work, not a rendering hint — how (and whether) a batch of
	// a given size is shown is the renderer's business.
	Total int
}

// Span is work in flight. End is called exactly once, and callers should defer
// it so a panic cannot strand a live row.
type Span interface {
	End(status Status, err error)
}

// Reporter observes work. Begin returns a context carrying the new span, so a
// Begin nested under it can find its parent. The returned context is local to
// the caller: siblings each derive their own from the same parent, and none of
// them mutate it.
type Reporter interface {
	Begin(ctx context.Context, ev Event) (context.Context, Span)
}

type nopSpan struct{}

func (nopSpan) End(Status, error) {}

type nopReporter struct{}

// Begin returns ctx unwrapped. Boxing the zero-size nopSpan into the Span
// interface does not allocate, so an unobserved run costs nothing per node.
func (nopReporter) Begin(ctx context.Context, _ Event) (context.Context, Span) {
	return ctx, nopSpan{}
}

// Nop discards everything. It is what From returns when no Reporter was
// installed, which is the case for every non-CLI caller.
var Nop Reporter = nopReporter{}

type reporterKey struct{}

// WithReporter installs r for retrieval by From. A nil r leaves ctx unchanged.
func WithReporter(ctx context.Context, r Reporter) context.Context {
	if r == nil {
		return ctx
	}
	return context.WithValue(ctx, reporterKey{}, r)
}

// From returns the Reporter in ctx, or Nop. It never returns nil, so callers
// can write observe.From(ctx).Begin(...) without a guard.
func From(ctx context.Context) Reporter {
	if r, ok := ctx.Value(reporterKey{}).(Reporter); ok && r != nil {
		return r
	}
	return Nop
}

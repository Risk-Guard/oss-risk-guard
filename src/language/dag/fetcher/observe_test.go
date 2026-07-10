package fetcher_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/environment"
	"github.com/Risk-Guard/oss-risk-guard/src/language"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/fetcher"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"github.com/Risk-Guard/oss-risk-guard/src/observe"
	"github.com/Risk-Guard/oss-risk-guard/src/runpath"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	"go.uber.org/zap"
)

// spyReporter records the spans a node emits. It stands in for src/ui, which
// this package must never import.
type spyReporter struct {
	mu     sync.Mutex
	begun  []observe.Event
	ended  map[string]observe.Status
	errors map[string]error
}

type spySpan struct {
	r  *spyReporter
	ev observe.Event
}

func newSpy() *spyReporter {
	return &spyReporter{ended: map[string]observe.Status{}, errors: map[string]error{}}
}

func (r *spyReporter) Begin(ctx context.Context, ev observe.Event) (context.Context, observe.Span) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.begun = append(r.begun, ev)
	return ctx, &spySpan{r: r, ev: ev}
}

func (s *spySpan) End(status observe.Status, err error) {
	s.r.mu.Lock()
	defer s.r.mu.Unlock()
	key := s.ev.Kind + ":" + s.ev.Name
	s.r.ended[key] = status
	if err != nil {
		s.r.errors[key] = err
	}
}

func (r *spyReporter) eventsOfKind(kind string) []observe.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []observe.Event
	for _, e := range r.begun {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

func spyCtx(t *testing.T, r observe.Reporter) context.Context {
	t.Helper()
	ctx := ctxutil.SetLogger(context.Background(), zap.NewNop())
	cfg := &environment.Config{}
	ctx = environment.SetConfig(ctx, cfg)
	ctx = environment.SetSharedConfig(ctx, cfg)
	ctx = runpath.SetCacheDir(ctx, t.TempDir())
	return observe.WithReporter(ctx, r)
}

// The renderer needs the package count up front to decide whether the batch is
// worth showing and to number the completion lines. If the fetcher stops passing
// Total, the CLI silently prints "(1/0)" — so assert the wiring, not just that
// some span was emitted.
func TestExecuteReportsBatchWithPackageTotal(t *testing.T) {
	spy := newSpy()
	ctx := spyCtx(t, spy)

	languages := map[string]language.Language{
		"npm":  &mockLanguage{ecosystem: "npm", response: &language.RegistryResponse{StatusCode: 200}},
		"pypi": &mockLanguage{ecosystem: "pypi", response: &language.RegistryResponse{StatusCode: 200}},
	}
	node := fetcher.NewNode(languages, nil)
	input := &dag_impl.Input{Packages: []models.PackageInfo{
		{Ecosystem: "npm", Name: "express"},
		{Ecosystem: "npm", Name: "lodash"},
		{Ecosystem: "pypi", Name: "requests"},
	}}

	if _, err := node.Execute(ctx, *input); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	batches := spy.eventsOfKind(observe.KindBatch)
	if len(batches) != 1 {
		t.Fatalf("emitted %d batch spans, want 1", len(batches))
	}
	if batches[0].Total != 3 {
		t.Errorf("batch Total = %d, want 3 (the deduped package count)", batches[0].Total)
	}
	if batches[0].Name == "" {
		t.Error("batch Name is empty; the renderer builds its header from it")
	}

	pkgs := spy.eventsOfKind(observe.KindPackage)
	if len(pkgs) != 3 {
		t.Fatalf("emitted %d package spans, want 3", len(pkgs))
	}
	got := map[string]bool{}
	for _, e := range pkgs {
		got[e.Name] = true
	}
	for _, want := range []string{"npm/express", "npm/lodash", "pypi/requests"} {
		if !got[want] {
			t.Errorf("no package span named %q; got %v", want, got)
		}
	}
}

// Total must reflect the deduped set, or the counter overshoots its own total.
func TestExecuteBatchTotalIsDeduped(t *testing.T) {
	spy := newSpy()
	ctx := spyCtx(t, spy)

	languages := map[string]language.Language{
		"npm": &mockLanguage{ecosystem: "npm", response: &language.RegistryResponse{StatusCode: 200}},
	}
	node := fetcher.NewNode(languages, nil)
	input := &dag_impl.Input{Packages: []models.PackageInfo{
		{Ecosystem: "npm", Name: "express"},
		{Ecosystem: "npm", Name: "express"},
	}}

	if _, err := node.Execute(ctx, *input); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	batches := spy.eventsOfKind(observe.KindBatch)
	if len(batches) != 1 || batches[0].Total != 1 {
		t.Fatalf("batch Total = %v, want 1 after dedupe", batches)
	}
	if n := len(spy.eventsOfKind(observe.KindPackage)); n != 1 {
		t.Fatalf("emitted %d package spans, want 1 after dedupe", n)
	}
}

// A failed fetch ends its span as an error, which is what makes the CLI print
// "✗" instead of "✓".
func TestExecuteReportsFailedPackageAsError(t *testing.T) {
	spy := newSpy()
	ctx := spyCtx(t, spy)

	boom := errors.New("registry 500")
	languages := map[string]language.Language{
		"npm":  &mockLanguage{ecosystem: "npm", err: boom},
		"pypi": &mockLanguage{ecosystem: "pypi", response: &language.RegistryResponse{StatusCode: 200}},
	}
	node := fetcher.NewNode(languages, nil)
	input := &dag_impl.Input{Packages: []models.PackageInfo{
		{Ecosystem: "npm", Name: "express"},
		{Ecosystem: "pypi", Name: "requests"},
	}}

	// A partial failure surfaces as an error from Execute; the spans still resolve.
	_, _ = node.Execute(ctx, *input)

	spy.mu.Lock()
	defer spy.mu.Unlock()
	if got := spy.ended["package:npm/express"]; got != observe.StatusError {
		t.Errorf("failed package ended as %q, want %q", got, observe.StatusError)
	}
	if got := spy.ended["package:pypi/requests"]; got != observe.StatusOK {
		t.Errorf("successful package ended as %q, want %q", got, observe.StatusOK)
	}
	if !errors.Is(spy.errors["package:npm/express"], boom) {
		t.Errorf("failed span did not carry the fetch error, got %v", spy.errors["package:npm/express"])
	}
}

// The batch reports the outcome of the fetch as a whole, not an unconditional
// success.
func TestExecuteBatchStatusReflectsFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want observe.Status
	}{
		{"all succeed", nil, observe.StatusOK},
		{"a package fails", errors.New("registry 500"), observe.StatusError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spy := newSpy()
			ctx := spyCtx(t, spy)

			languages := map[string]language.Language{
				"npm": &mockLanguage{ecosystem: "npm", err: tc.err, response: &language.RegistryResponse{StatusCode: 200}},
			}
			node := fetcher.NewNode(languages, nil)
			input := &dag_impl.Input{Packages: []models.PackageInfo{
				{Ecosystem: "npm", Name: "a"},
				{Ecosystem: "npm", Name: "b"},
			}}
			_, _ = node.Execute(ctx, *input)

			spy.mu.Lock()
			defer spy.mu.Unlock()
			if got := spy.ended["batch:registry metadata"]; got != tc.want {
				t.Errorf("batch ended as %q, want %q", got, tc.want)
			}
		})
	}
}

// Every span the fetcher opens must be closed, even when a package fails, or a
// row is stranded on screen for the rest of the run.
func TestExecuteClosesEverySpan(t *testing.T) {
	spy := newSpy()
	ctx := spyCtx(t, spy)

	languages := map[string]language.Language{
		"npm": &mockLanguage{ecosystem: "npm", err: errors.New("boom")},
	}
	node := fetcher.NewNode(languages, nil)
	input := &dag_impl.Input{Packages: []models.PackageInfo{
		{Ecosystem: "npm", Name: "a"},
		{Ecosystem: "npm", Name: "b"},
	}}

	_, _ = node.Execute(ctx, *input)

	spy.mu.Lock()
	defer spy.mu.Unlock()
	if len(spy.begun) != len(spy.ended) {
		t.Fatalf("began %d spans but ended %d", len(spy.begun), len(spy.ended))
	}
}

// With no packages the node returns early, before opening a batch.
func TestExecuteNoPackagesEmitsNoSpans(t *testing.T) {
	spy := newSpy()
	ctx := spyCtx(t, spy)

	node := fetcher.NewNode(map[string]language.Language{}, nil)
	if _, err := node.Execute(ctx, dag_impl.Input{}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(spy.begun) != 0 {
		t.Fatalf("emitted %d spans for an empty package list, want 0", len(spy.begun))
	}
}

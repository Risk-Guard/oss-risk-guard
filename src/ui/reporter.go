package ui

import (
	"context"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/observe"
)

// reporter turns observe spans into rows. It is the only thing that knows a
// "fetcher node started" should read "(fetching registry metadata)".
type reporter struct{ ui *UI }

type spanKey struct{}

// batchState is shared by a batch span and its package children.
type batchState struct {
	note   string
	total  int
	done   int  // completions so far; guarded by UI.mu
	silent bool // a batch of one is not worth announcing
}

// liveSpan is one in-flight observe.Span.
//
// Which fields are set depends on kind: a phase or package span owns a row; a
// node span instead annotates the nearest enclosing phase row; a batch span
// owns no row at all and exists to carry the counter its children report into.
type liveSpan struct {
	ui     *UI
	parent *liveSpan
	kind   string
	name   string

	row   *row        // phase and package spans; nil when rows are suppressed
	prow  *row        // node spans: the phase row this annotates
	label string      // node spans: the label registered on prow.active
	batch *batchState // batch spans own it, package spans borrow their parent's
}

func (r *reporter) Begin(ctx context.Context, ev observe.Event) (context.Context, observe.Span) {
	parent, _ := ctx.Value(spanKey{}).(*liveSpan)
	s := &liveSpan{ui: r.ui, parent: parent, kind: ev.Kind, name: ev.Name}

	switch ev.Kind {
	case observe.KindPhase:
		s.row = r.ui.startRow(ev.Name, true, "", ev.Total)

	case observe.KindBatch:
		s.batch = &batchState{
			note:   "fetching " + ev.Name,
			total:  ev.Total,
			silent: ev.Total <= 1,
		}
		if !s.batch.silent {
			r.ui.Printf("Fetching %s for %d packages…\n", ev.Name, ev.Total)
		}

	case observe.KindPackage:
		s.batch = batchOf(parent)
		if s.batch != nil && !s.batch.silent {
			s.row = r.ui.startRow(ev.Name, false, s.batch.note, 0)
		}

	default: // a DAG node, running inside some phase
		s.label = nodeDisplayName(ev.Type)
		s.prow = phaseRowOf(parent)
		r.ui.addActive(s.prow, s)
	}

	return context.WithValue(ctx, spanKey{}, s), s
}

func (s *liveSpan) End(status observe.Status, _ error) {
	switch s.kind {
	case observe.KindPhase:
		s.ui.removeRow(s.row)
	case observe.KindBatch:
		// The header was printed at Begin; the children report their own
		// completions. Nothing to retract.
	case observe.KindPackage:
		s.ui.finishPackage(s, status)
	default:
		s.ui.removeActive(s.prow, s)
	}
}

// phaseRowOf finds the row a node span should annotate: the nearest enclosing
// phase. A node running outside any phase (or with rows suppressed) gets nil,
// and annotating nil is a no-op.
func phaseRowOf(s *liveSpan) *row {
	for ; s != nil; s = s.parent {
		if s.row != nil && s.row.phase {
			return s.row
		}
	}
	return nil
}

func batchOf(s *liveSpan) *batchState {
	for ; s != nil; s = s.parent {
		if s.batch != nil {
			return s.batch
		}
	}
	return nil
}

// startRow adds a live row, or returns nil when rows are suppressed.
func (u *UI) startRow(text string, phase bool, note string, total int) *row {
	if !u.enabled {
		return nil
	}
	rw := &row{text: text, start: time.Now(), phase: phase, note: note, total: total}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.addRowLocked(rw)
	return rw
}

func (u *UI) addActive(rw *row, s *liveSpan) {
	if rw == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	rw.active = append(rw.active, s)
	u.redrawLocked()
}

func (u *UI) removeActive(rw *row, s *liveSpan) {
	if rw == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	rw.dropActive(s)
	u.redrawLocked()
}

// finishPackage retires a package row and locks its result in above the
// remaining rows. The completion counter lives here, so the "(3/12)" on the
// line and the rows on screen can never disagree about how many are done.
func (u *UI) finishPackage(s *liveSpan, status observe.Status) {
	b := s.batch
	if b == nil || b.silent {
		return
	}
	u.removeRow(s.row)

	u.mu.Lock()
	b.done++
	done, total := b.done, b.total
	u.mu.Unlock()

	mark := "✓"
	if status == observe.StatusError {
		mark = "✗"
	}
	u.Printf("%s %s  (%d/%d)\n", mark, s.name, done, total)
}

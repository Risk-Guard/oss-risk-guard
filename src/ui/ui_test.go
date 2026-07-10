package ui

import (
	"context"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/observe"
)

// NewContext must install both halves: the UI for cmd-level printing and the
// Reporter that domain code reaches through observe. Installing one without the
// other silently loses every progress row.
func TestNewContextInstallsUIAndReporter(t *testing.T) {
	u := New(&syncBuf{}, false, 0)
	ctx := NewContext(context.Background(), u)

	if FromContext(ctx) != u {
		t.Fatal("FromContext did not return the installed UI")
	}
	if observe.From(ctx) == observe.Nop {
		t.Fatal("NewContext did not install a Reporter")
	}
	if r, ok := observe.From(ctx).(*reporter); !ok || r.ui != u {
		t.Fatal("the installed Reporter is not backed by this UI")
	}
}

// A context that never passed through NewContext — the server, library callers,
// tests — reports to Nop and prints nowhere. This is the isolation guarantee.
func TestUnwiredContextIsSilent(t *testing.T) {
	ctx := context.Background()

	if observe.From(ctx) != observe.Nop {
		t.Fatal("an unwired context must report to Nop")
	}
	_, span := observe.From(ctx).Begin(ctx, observe.Event{Kind: observe.KindPhase, Name: "x"})
	span.End(observe.StatusOK, nil)

	if FromContext(ctx).enabled {
		t.Fatal("an unwired context must not yield a painting UI")
	}
}

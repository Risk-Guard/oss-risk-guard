package overrides

import (
	"context"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestStore(t *testing.T) {
	t.Run("GetAll returns overrides in original order", func(t *testing.T) {
		store := NewStore([]Override{
			{Path: "source_url", Value: "https://a.com", Reason: "r1"},
			{Path: "license", Value: "MIT", Reason: "r2"},
		})

		all := store.GetAll()
		if len(all) != 2 {
			t.Fatalf("expected 2 overrides, got %d", len(all))
		}
		if all[0].Path != "source_url" || all[1].Path != "license" {
			t.Error("overrides not in original order")
		}
	})

	t.Run("GetAll returns copy", func(t *testing.T) {
		store := NewStore([]Override{
			{Path: "source_url", Value: "https://a.com", Reason: "r1"},
		})

		all := store.GetAll()
		all[0].Path = "mutated"

		original := store.GetAll()
		if original[0].Path != "source_url" {
			t.Error("GetAll returned a reference, not a copy")
		}
	})

	t.Run("records applied overrides", func(t *testing.T) {
		store := NewStore(nil)

		store.RecordApplied(AppliedOverride{Path: "source_url", Reason: "fix"})

		applied := store.GetApplied()
		if len(applied) != 1 {
			t.Fatalf("expected 1 applied, got %d", len(applied))
		}
		if applied[0].Path != "source_url" {
			t.Errorf("expected path source_url, got %s", applied[0].Path)
		}
	})

	t.Run("nil overrides creates empty store", func(t *testing.T) {
		store := NewStore(nil)
		if len(store.GetAll()) != 0 {
			t.Error("expected empty overrides")
		}
		if len(store.GetApplied()) != 0 {
			t.Error("expected empty applied")
		}
	})
}

func TestWarnUnconsumed(t *testing.T) {
	t.Run("warns on unconsumed overrides", func(t *testing.T) {
		core, logs := observer.New(zap.WarnLevel)
		log := zap.New(core)
		ctx := ctxutil.SetLogger(context.Background(), log)

		store := NewStore([]Override{
			{Path: "source_url", Value: "https://a.com", Reason: "applied one"},
			{Path: "bogus_field", Value: "whatever", Reason: "never applied"},
		})
		store.RecordApplied(AppliedOverride{Path: "source_url", Reason: "applied one"})

		store.WarnUnconsumed(ctx)

		if logs.Len() != 1 {
			t.Fatalf("expected 1 warning, got %d", logs.Len())
		}
		entry := logs.All()[0]
		if entry.Message != "override was not applied by any node" {
			t.Errorf("unexpected message: %s", entry.Message)
		}
	})

	t.Run("does not warn on unapplied fallback override", func(t *testing.T) {
		core, logs := observer.New(zap.WarnLevel)
		log := zap.New(core)
		ctx := ctxutil.SetLogger(context.Background(), log)

		store := NewStore([]Override{
			{Path: "source_url", Value: "https://a.com", Reason: "gap-fill", Precedence: "fallback"},
		})
		// Intentionally record nothing applied: the fallback gap-filled nothing
		// because a source was already resolved.

		store.WarnUnconsumed(ctx)

		if logs.Len() != 0 {
			t.Errorf("expected no warning for unapplied fallback, got %d", logs.Len())
		}
	})

	t.Run("no warnings when all consumed", func(t *testing.T) {
		core, logs := observer.New(zap.WarnLevel)
		log := zap.New(core)
		ctx := ctxutil.SetLogger(context.Background(), log)

		store := NewStore([]Override{
			{Path: "source_url", Value: "https://a.com", Reason: "r1"},
		})
		store.RecordApplied(AppliedOverride{Path: "source_url", Reason: "r1"})

		store.WarnUnconsumed(ctx)

		if logs.Len() != 0 {
			t.Errorf("expected no warnings, got %d", logs.Len())
		}
	})
}

package transformer

import (
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"github.com/Risk-Guard/oss-risk-guard/src/overrides"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

func newTestOutput(sourceURL string) *Output {
	url := sourceURL
	nextInput := &dag_impl.Input{SourceURL: nil}
	return NewOutput(
		executiondag.StatusSuccess,
		"ok",
		[]PackageOutput{
			{
				Ecosystem: "npm",
				Name:      "express",
				Metadata: &models.PackageMetadata{
					SourceURL: &url,
				},
			},
		},
		dag_impl.Input{},
		nextInput,
	)
}

func TestApplyOverridesV2(t *testing.T) {
	t.Run("source_url override applied to metadata", func(t *testing.T) {
		out := newTestOutput("https://old.com")

		applied, err := out.ApplyOverridesV2([]overrides.Override{
			{Path: "source_url", Value: "https://new.com", Reason: "fix"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if *out.Outputs[0].Metadata.SourceURL != "https://new.com" {
			t.Errorf("expected metadata source_url=https://new.com, got %s", *out.Outputs[0].Metadata.SourceURL)
		}
		if len(applied) != 1 {
			t.Fatalf("expected 1 applied, got %d", len(applied))
		}
		if applied[0].Path != "source_url" {
			t.Errorf("expected applied path=source_url, got %s", applied[0].Path)
		}
	})

	t.Run("source_url propagated to downstream input", func(t *testing.T) {
		out := newTestOutput("https://old.com")

		_, err := out.ApplyOverridesV2([]overrides.Override{
			{Path: "source_url", Value: "https://new.com", Reason: "fix"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if out.Output == nil {
			t.Fatal("expected Output (nextInput) to be set")
		}
		if out.Output.SourceURL == nil || *out.Output.SourceURL != "https://new.com" {
			t.Errorf("expected downstream source_url=https://new.com, got %v", out.Output.SourceURL)
		}
	})

	t.Run("unrecognized overrides skipped", func(t *testing.T) {
		out := newTestOutput("https://old.com")

		applied, err := out.ApplyOverridesV2([]overrides.Override{
			{Path: "some_other_field", Value: "whatever", Reason: "r"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(applied) != 0 {
			t.Errorf("expected 0 applied, got %d", len(applied))
		}
		if *out.Outputs[0].Metadata.SourceURL != "https://old.com" {
			t.Error("metadata should be unchanged")
		}
	})

	t.Run("invalid value type errors", func(t *testing.T) {
		out := newTestOutput("https://old.com")

		_, err := out.ApplyOverridesV2([]overrides.Override{
			{Path: "source_url", Value: 12345, Reason: "bad type"},
		})
		if err == nil {
			t.Fatal("expected error for non-string value")
		}
	})

	t.Run("empty string value errors", func(t *testing.T) {
		out := newTestOutput("https://old.com")

		_, err := out.ApplyOverridesV2([]overrides.Override{
			{Path: "source_url", Value: "", Reason: "empty"},
		})
		if err == nil {
			t.Fatal("expected error for empty string")
		}
	})

	t.Run("multi-package errors", func(t *testing.T) {
		nextInput := &dag_impl.Input{}
		out := NewOutput(
			executiondag.StatusSuccess,
			"ok",
			[]PackageOutput{
				{Ecosystem: "npm", Name: "a", Metadata: &models.PackageMetadata{}},
				{Ecosystem: "npm", Name: "b", Metadata: &models.PackageMetadata{}},
			},
			dag_impl.Input{},
			nextInput,
		)

		_, err := out.ApplyOverridesV2([]overrides.Override{
			{Path: "source_url", Value: "https://new.com", Reason: "fix"},
		})
		if err == nil {
			t.Fatal("expected error for multi-package source_url override")
		}
	})

	t.Run("nil metadata does not panic", func(t *testing.T) {
		nextInput := &dag_impl.Input{}
		out := NewOutput(
			executiondag.StatusSuccess,
			"ok",
			[]PackageOutput{
				{Ecosystem: "npm", Name: "a", Metadata: nil},
			},
			dag_impl.Input{},
			nextInput,
		)

		applied, err := out.ApplyOverridesV2([]overrides.Override{
			{Path: "source_url", Value: "https://new.com", Reason: "fix"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(applied) != 1 {
			t.Errorf("expected 1 applied, got %d", len(applied))
		}
	})

	t.Run("no overrides returns empty applied", func(t *testing.T) {
		out := newTestOutput("https://old.com")

		applied, err := out.ApplyOverridesV2(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(applied) != 0 {
			t.Errorf("expected 0 applied, got %d", len(applied))
		}
	})

	t.Run("returns applied with reason", func(t *testing.T) {
		out := newTestOutput("https://old.com")

		applied, err := out.ApplyOverridesV2([]overrides.Override{
			{Path: "source_url", Value: "https://new.com", Reason: "customer request #123"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(applied) != 1 {
			t.Fatalf("expected 1 applied, got %d", len(applied))
		}
		if applied[0].Reason != "customer request #123" {
			t.Errorf("expected reason preserved, got %s", applied[0].Reason)
		}
	})
}

// newTestOutputNoSource builds an Output with no resolved source on either the
// package metadata or the downstream Input.
func newTestOutputNoSource() *Output {
	return NewOutput(
		executiondag.StatusSuccess,
		"ok",
		[]PackageOutput{
			{Ecosystem: "npm", Name: "express", Metadata: &models.PackageMetadata{SourceURL: nil}},
		},
		dag_impl.Input{},
		&dag_impl.Input{SourceURL: nil},
	)
}

func TestApplyOverridesV2Precedence(t *testing.T) {
	t.Run("fallback applies when no source resolved", func(t *testing.T) {
		out := newTestOutputNoSource()

		applied, err := out.ApplyOverridesV2([]overrides.Override{
			{Path: "source_url", Value: "https://fb.com", Reason: "gap", Precedence: "fallback"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(applied) != 1 {
			t.Fatalf("expected 1 applied, got %d", len(applied))
		}
		if out.Outputs[0].Metadata.SourceURL == nil || *out.Outputs[0].Metadata.SourceURL != "https://fb.com" {
			t.Errorf("expected metadata source_url set to fallback, got %v", out.Outputs[0].Metadata.SourceURL)
		}
		if out.Output.SourceURL == nil || *out.Output.SourceURL != "https://fb.com" {
			t.Errorf("expected downstream source_url set to fallback, got %v", out.Output.SourceURL)
		}
	})

	t.Run("fallback skips when metadata source already set", func(t *testing.T) {
		out := newTestOutput("https://declared.com")

		applied, err := out.ApplyOverridesV2([]overrides.Override{
			{Path: "source_url", Value: "https://fb.com", Reason: "gap", Precedence: "fallback"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(applied) != 0 {
			t.Errorf("expected 0 applied (fallback should skip), got %d", len(applied))
		}
		if *out.Outputs[0].Metadata.SourceURL != "https://declared.com" {
			t.Errorf("declared metadata source must be preserved, got %s", *out.Outputs[0].Metadata.SourceURL)
		}
	})

	t.Run("fallback skips when only downstream input source set", func(t *testing.T) {
		declared := "https://declared.com"
		out := NewOutput(
			executiondag.StatusSuccess,
			"ok",
			[]PackageOutput{
				{Ecosystem: "npm", Name: "express", Metadata: &models.PackageMetadata{SourceURL: nil}},
			},
			dag_impl.Input{},
			&dag_impl.Input{SourceURL: &declared},
		)

		applied, err := out.ApplyOverridesV2([]overrides.Override{
			{Path: "source_url", Value: "https://fb.com", Reason: "gap", Precedence: "fallback"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(applied) != 0 {
			t.Errorf("expected 0 applied (fallback should skip), got %d", len(applied))
		}
		if *out.Output.SourceURL != "https://declared.com" {
			t.Errorf("declared downstream source must be preserved, got %s", *out.Output.SourceURL)
		}
	})

	t.Run("force overrides even when source already set", func(t *testing.T) {
		out := newTestOutput("https://declared.com")

		applied, err := out.ApplyOverridesV2([]overrides.Override{
			{Path: "source_url", Value: "https://fb.com", Reason: "correction", Precedence: "force"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(applied) != 1 {
			t.Fatalf("expected 1 applied, got %d", len(applied))
		}
		if *out.Outputs[0].Metadata.SourceURL != "https://fb.com" {
			t.Errorf("force must override, got %s", *out.Outputs[0].Metadata.SourceURL)
		}
	})

	t.Run("empty precedence behaves like force", func(t *testing.T) {
		out := newTestOutput("https://declared.com")

		applied, err := out.ApplyOverridesV2([]overrides.Override{
			{Path: "source_url", Value: "https://fb.com", Reason: "correction"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(applied) != 1 {
			t.Fatalf("expected 1 applied, got %d", len(applied))
		}
		if *out.Outputs[0].Metadata.SourceURL != "https://fb.com" {
			t.Errorf("empty precedence must override, got %s", *out.Outputs[0].Metadata.SourceURL)
		}
	})
}

package source_repo_not_found

import (
	"context"
	"testing"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/storage"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	"go.uber.org/zap"
)

// A package whose metadata defines no source repository must be flagged, not
// silently skipped: its provenance can't be verified.
func TestExecute_NoSourceURLIsViolation(t *testing.T) {
	ctx := ctxutil.SetLogger(context.Background(), zap.NewNop())
	node := NewNode()

	empty := ""
	for _, tc := range []struct {
		name string
		url  *string
	}{
		{"nil url", nil},
		{"empty url", &empty},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := node.Execute(ctx, dag_impl.Input{SourceURL: tc.url})
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if out.Check.CheckStatus != storage.StatusViolation {
				t.Errorf("expected violation for missing source URL, got %v", out.Check.CheckStatus)
			}
			if out.Check.CheckCode != node.Code {
				t.Errorf("expected code %s, got %s", node.Code, out.Check.CheckCode)
			}
		})
	}
}

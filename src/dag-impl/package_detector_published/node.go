package package_detector_published

import (
	"context"
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_published_content"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/package_detector"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/def"

	"go.uber.org/zap"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

// Node detects packages in the source tree checked out at the published
// version's gitHead, for provenance checks (e.g. PACKAGE_NAME_MISMATCH) that
// must compare the published artifact against its source as-published. When no
// gitHead tree exists — the common case for non-npm ecosystems, versions without
// a recorded gitHead, or an unreachable gitHead — it falls back to the HEAD
// package detection so the consuming checks behave exactly as before.
type Node struct {
	Description string `json:"description,omitempty"`
	ecosystems  []def.Ecosystem
}

func NewNode(ecosystems []def.Ecosystem) *Node {
	return &Node{
		Description: "Detects packages in the source tree at the published version's gitHead, falling back to HEAD",
		ecosystems:  ecosystems,
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*Output, error) {
	logger := ctxutil.GetLogger(ctx)

	publishedOut := executiondag.GetOutput[*git_clone_published_content.Node](ctx).(*git_clone_published_content.Output)
	headOut := executiondag.GetOutput[*package_detector.Node](ctx).(*package_detector.Output)

	// No published (gitHead) tree available: fall back transparently to the HEAD
	// detector, mirroring its status and manifests so consumers behave exactly as
	// if they depended on package_detector directly (including auto-skip
	// propagation when HEAD detection itself was skipped).
	if publishedOut.GetStatus() != executiondag.StatusSuccess || publishedOut.RepoPath == "" {
		logger.Debug("no published tree; using HEAD package detection",
			zap.String("published_status", string(publishedOut.GetStatus())),
			zap.String("head_status", string(headOut.GetStatus())))
		reason := headOut.GetStatusReason()
		if headOut.GetStatus() == executiondag.StatusSuccess {
			reason = "no gitHead; detected from HEAD"
		}
		out := NewOutput(headOut.GetStatus(), reason, headOut.DetectedManifests, input)
		out.SourceRef = SourceRefHead
		return out, nil
	}

	manifests, err := package_detector.DetectAndEnrich(publishedOut.RepoPath, n.ecosystems, input.AnalysisIdentifier)
	if err != nil {
		return nil, fmt.Errorf("detecting packages in published tree: %w", err)
	}

	// The published clone pins the commit in order of assurance: verified build
	// provenance (strongest), else the attested gitHead, else a release tag matching
	// the version (publishedOut.Ref names the tag/provenance ref).
	sourceRef, at := SourceRefGitHead, "gitHead "+publishedOut.Commit
	switch {
	case publishedOut.ProvenanceVerified:
		sourceRef, at = SourceRefProvenance, "verified provenance "+publishedOut.Commit
	case publishedOut.Ref != "":
		sourceRef, at = SourceRefTag, "tag "+publishedOut.Ref
	}

	logger.Info("detected packages in published tree",
		zap.Int("count", len(manifests)),
		zap.String("commit", publishedOut.Commit),
		zap.String("ref", publishedOut.Ref))
	out := NewOutput(executiondag.StatusSuccess,
		fmt.Sprintf("detected %d package(s) at %s", len(manifests), at),
		manifests, input)
	out.SourceRef = sourceRef
	out.SourceCommit = publishedOut.Commit
	out.SourceRefName = publishedOut.Ref
	return out, nil
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*git_clone_published_content.Node](),
		executiondag.DependsOn[*package_detector.Node](),
	}
}

// AllowAutoSkip returns false so this node still runs when the published clone is
// skipped (no gitHead) — that is precisely when it must fall back to HEAD.
func (n *Node) AllowAutoSkip() bool { return false }

func (n *Node) CreateSkippedOutput(reason string, input dag_impl.Input) *Output {
	return NewOutput(executiondag.StatusSkipped, reason, nil, input)
}

func (n *Node) Kind() string { return "transform" }

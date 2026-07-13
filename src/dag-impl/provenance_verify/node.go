// Package provenance_verify is a DAG node that verifies a package version's npm
// build-provenance (Sigstore) attestation and compares the attested source
// repository against the analyzed repository. It produces one shared fact —
// whether the published artifact is cryptographically bound to its declared
// source — consumed by PACKAGE_NAME_MISMATCH, PACKAGE_SOURCE_URL_MISMATCH, and
// PACKAGE_INVALID_ARTIFACT, and used to pin the published-source clone commit.
package provenance_verify

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/common"
	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	httputil "github.com/Risk-Guard/oss-risk-guard/src/http"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/transformer"
	"github.com/Risk-Guard/oss-risk-guard/src/provenance"

	"go.uber.org/zap"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_resolve"
	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

// attestationCacheMaxAge is long because an attestation bundle is immutable for a
// published version.
const attestationCacheMaxAge = 30 * 24 * time.Hour

type Node struct {
	Description string `json:"description,omitempty"`
	verifier    provenance.Verifier
}

func NewNode(verifier provenance.Verifier) *Node {
	return &Node{
		Description: "Verifies npm build-provenance (Sigstore) attestations against the declared source repo",
		verifier:    verifier,
	}
}

func (n *Node) GetDependencies() []any {
	return []any{
		executiondag.DependsOn[*transformer.Node](),
		executiondag.DependsOn[*git_resolve.Node](),
	}
}

// AllowAutoSkip returns false so this node still runs (and yields a determinate
// "no attestation" result) even when git_resolve or transformer skip — so it never
// forces its dependent checks to auto-skip.
func (n *Node) AllowAutoSkip() bool { return false }

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*Output, error) {
	log := ctxutil.GetLogger(ctx)

	transformerOut := executiondag.GetOutput[*transformer.Node](ctx).(*transformer.Output)
	resolveOut := executiondag.GetOutput[*git_resolve.Node](ctx).(*git_resolve.Output)

	// The DAG is scoped to one source URL; verify the first package that advertises
	// a provenance attestation with a sha512 artifact hash to bind the signature to.
	for _, pkg := range input.Packages {
		meta := transformerOut.GetPackageMetadata(pkg.Ecosystem, pkg.Name)
		if meta == nil || meta.Distribution == nil {
			continue
		}
		dist := meta.Distribution
		if dist.AttestationURL == "" || dist.HashAlgorithm != "sha512" || dist.Hash == "" {
			continue
		}

		bundleBytes, err := n.fetchBundle(ctx, dist.AttestationURL)
		if err != nil {
			// A fetch failure is not evidence of tampering; leave it unverified and
			// let checks fall through to today's behavior rather than flag a finding.
			log.Info("attestation fetch failed; provenance left unverified",
				zap.String("package", pkg.Name), zap.Error(err))
			return n.result(provenance.Result{FailReason: provenance.FailNoAttestation}, input), nil
		}

		res, err := n.verifier.Verify(ctx, provenance.Request{
			Bundle:         bundleBytes,
			ArtifactSHA512: dist.Hash,
			PackageName:    pkg.Name,
			Version:        derefString(meta.Version),
		})
		if err != nil {
			log.Info("provenance verification error; left unverified",
				zap.String("package", pkg.Name), zap.Error(err))
			return n.result(provenance.Result{FailReason: provenance.FailNoAttestation}, input), nil
		}

		// A validly-signed attestation that names a different repo than the one we
		// analyzed is a repo mismatch, not a trusted binding to the declared source.
		if res.Verified && !sameRepo(res.SourceRepo, resolveOut.NormalizedURL) {
			log.Info("provenance attests a different repo than declared",
				zap.String("attested", res.SourceRepo), zap.String("declared", resolveOut.NormalizedURL))
			res.Verified = false
			res.FailReason = provenance.FailRepoMismatch
		}

		if res.Verified {
			log.Info("build provenance verified",
				zap.String("package", pkg.Name),
				zap.String("repo", res.SourceRepo),
				zap.String("ref", res.Ref))
		}
		return n.result(res, input), nil
	}

	return n.result(provenance.Result{FailReason: provenance.FailNoAttestation}, input), nil
}

// result wraps a provenance.Result as a StatusSuccess output — the node reports a
// determinate verdict (including "no attestation"), never a skip, so it can never
// auto-skip its dependents.
func (n *Node) result(res provenance.Result, input dag_impl.Input) *Output {
	return NewOutput(executiondag.StatusSuccess, provenanceReason(res), res, input)
}

func (n *Node) fetchBundle(ctx context.Context, url string) ([]byte, error) {
	raw, err := httputil.GetJSONCached[json.RawMessage](ctx, url, &httputil.CacheOptions{MaxAge: attestationCacheMaxAge})
	if err != nil {
		return nil, err
	}
	return []byte(*raw), nil
}

// sameRepo compares an attested source repo to the declared/normalized repo after
// normalization, so scheme/suffix differences don't cause false mismatches.
func sameRepo(attested, declared string) bool {
	if attested == "" || declared == "" {
		return false
	}
	return common.NormalizeSourceURL(attested) == common.NormalizeSourceURL(declared)
}

func provenanceReason(res provenance.Result) string {
	switch {
	case res.Verified:
		return "provenance verified: built from " + res.SourceRepo
	case res.FailReason == provenance.FailNone, res.FailReason == provenance.FailNoAttestation:
		return "no verifiable build provenance"
	default:
		return "provenance not verified: " + string(res.FailReason)
	}
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (n *Node) CreateSkippedOutput(reason string, input dag_impl.Input) *Output {
	return NewOutput(executiondag.StatusSkipped, reason, provenance.Result{FailReason: provenance.FailNoAttestation}, input)
}

func (n *Node) Kind() string { return "fetch" }

func (n *Node) Read(ctx context.Context, input dag_impl.Input) (*Output, error) {
	output, err := dag_impl.ReadOutput[*Output](ctx, input)
	if err != nil {
		return n.result(provenance.Result{FailReason: provenance.FailNoAttestation}, input), nil
	}
	return output, nil
}

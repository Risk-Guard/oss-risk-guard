package git_clone_published_content

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_clone_content"
	"github.com/Risk-Guard/oss-risk-guard/src/dag-impl/git_resolve"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/def"
	"github.com/Risk-Guard/oss-risk-guard/src/git"
	"github.com/Risk-Guard/oss-risk-guard/src/language/dag/transformer"

	"go.uber.org/zap"

	dag_impl "github.com/Risk-Guard/oss-risk-guard/src/dag-impl"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

// repoDirName is deliberately distinct from git_clone_content's "repo" so the
// published-version tree and the HEAD tree never clobber each other on disk.
const repoDirName = "repo-published"

// Node clones the source tree at the analyzed version's gitHead — the commit the
// package was published from — for provenance checks that must compare the
// published artifact against its source as-published rather than current HEAD.
// It is a no-op (skipped) whenever no usable gitHead is available, in which case
// downstream provenance checks fall back to the HEAD clone.
type Node struct {
	isLocal            bool
	ecosystems         []def.Ecosystem
	Description        string `json:"description,omitempty"`
	deps               []any
	sparseCheckoutHash string
}

func NewNode(isLocal bool, deps []any, ecosystems []def.Ecosystem) *Node {
	return &Node{
		Description:        "Clones the source tree at the published version's gitHead commit for provenance checks",
		deps:               deps,
		isLocal:            isLocal,
		ecosystems:         ecosystems,
		sparseCheckoutHash: git_clone_content.HashPatterns(git_clone_content.BuildSparsePatterns(ecosystems)),
	}
}

func (n *Node) Execute(ctx context.Context, input dag_impl.Input) (*Output, error) {
	log := ctxutil.GetLogger(ctx)

	if !input.HasSourceURL() {
		return NewOutput(executiondag.StatusSkipped, "no source URL provided", "", "", input), nil
	}
	// gitHead is a registry (e.g. npm) concept for a remotely-published version;
	// a local source has no published commit to pin to.
	if n.isLocal {
		return NewOutput(executiondag.StatusSkipped, "local source has no published gitHead", "", "", input), nil
	}

	commit, ref := resolvePublishedSource(ctx, input)
	if commit == "" {
		return NewOutput(executiondag.StatusSkipped, "no gitHead or version tag available for analyzed version", "", "", input), nil
	}

	resolveOut := executiondag.GetOutput[*git_resolve.Node](ctx).(*git_resolve.Output)

	m, err := git_clone_content.Materialize(ctx, git_clone_content.MaterializeParams{
		SourceURL:          *input.SourceURL,
		IsLocal:            false,
		CommitSHA:          commit,
		RepoDirName:        repoDirName,
		SparseCheckoutHash: n.sparseCheckoutHash,
		Patterns:           git_clone_content.BuildSparsePatterns(n.ecosystems),
		NormalizedURL:      resolveOut.NormalizedURL,
		IsPrivate:          resolveOut.IsPrivate,
		Trusted:            input.Trusted,
	}, input)
	if err != nil {
		// A commit that no longer resolves on the remote (force-push, deleted
		// branch/tag, unadvertised SHA) is a source-owner data problem, not a fatal
		// error. Skip so the published detector falls back to HEAD instead of
		// halting the DAG.
		log.Info("published clone failed; provenance checks will fall back to HEAD",
			zap.String("commit", commit), zap.String("ref", ref), zap.Error(err))
		return NewOutput(executiondag.StatusSkipped,
			fmt.Sprintf("cloning published source %s: %v", commit, err), "", "", input), nil
	}

	out := NewOutput(m.Status, m.Reason, m.RepoPath, m.Commit, input)
	out.Ref = ref
	return out, nil
}

// resolvePublishedSource pins the source tree for the analyzed version. It prefers
// the registry-attested gitHead (a full SHA the version was published from); when
// none is recorded it falls back to resolving a release tag that matches the
// version on the remote. It returns the resolved commit SHA and, for the tag
// fallback, the matched tag ref name (empty for a gitHead). Returns ("","") when
// neither is available, so the caller skips to the HEAD fallback. The DAG is
// scoped to a single source URL, so the first package that resolves identifies the
// published commit for that source.
func resolvePublishedSource(ctx context.Context, input dag_impl.Input) (commit, ref string) {
	transformerOut := executiondag.GetOutput[*transformer.Node](ctx).(*transformer.Output)

	// First choice: an attested gitHead (the only form git can fetch by directly).
	for _, pkg := range input.Packages {
		meta := transformerOut.GetPackageMetadata(pkg.Ecosystem, pkg.Name)
		if meta == nil || meta.GitHead == nil {
			continue
		}
		if git.IsFullSHA(*meta.GitHead) {
			return *meta.GitHead, ""
		}
	}

	// Fallback: resolve a release tag matching the version on the remote.
	return resolveVersionTag(ctx, input, transformerOut)
}

// resolveVersionTag looks up a git tag matching a package's version on the remote,
// for versions the registry published without a gitHead. It queries once per
// package with a "*<version>" glob (a single ls-remote round-trip) and selects the
// tag that best identifies the package version. Returns the resolved SHA and tag
// ref name, or ("","") when no version tag resolves.
func resolveVersionTag(ctx context.Context, input dag_impl.Input, transformerOut *transformer.Output) (commit, ref string) {
	log := ctxutil.GetLogger(ctx)

	for _, pkg := range input.Packages {
		version := pkg.Version
		if meta := transformerOut.GetPackageMetadata(pkg.Ecosystem, pkg.Name); meta != nil && meta.Version != nil && *meta.Version != "" {
			version = *meta.Version
		}
		if version == "" || !git.IsSafeTagVersion(version) {
			continue
		}

		refs, err := git.ListRemoteRefs(ctx, *input.SourceURL, "*"+version)
		if err != nil {
			log.Info("version tag lookup failed; will fall back to HEAD",
				zap.String("package", pkg.Name), zap.String("version", version), zap.Error(err))
			continue
		}

		if name, sha := selectVersionTag(refs, pkg.Name, version); sha != "" {
			log.Info("resolved published source via version tag",
				zap.String("package", pkg.Name), zap.String("tag", name), zap.String("commit", sha))
			return sha, name
		}
	}
	return "", ""
}

const tagRefPrefix = "refs/tags/"

// selectVersionTag picks the tag ref that best identifies pkgName@version from the
// refs returned by a "*<version>" ls-remote glob. The glob is a coarse filter — it
// also matches unrelated tags (e.g. "16.3.1" for "6.3.1") and, in a monorepo,
// sibling packages' tags — so candidates are validated to encode exactly this
// version and ranked by specificity: a package-scoped tag ("<pkg>@<version>") is
// unambiguous and preferred over a bare release tag ("v<version>"/"<version>").
func selectVersionTag(refs []git.RemoteRef, pkgName, version string) (name, sha string) {
	candidates := []string{
		pkgName + "@" + version,
		pkgName + "@v" + version,
		"v" + version,
		version,
	}
	for _, want := range candidates {
		for _, r := range refs {
			if strings.TrimPrefix(r.Name, tagRefPrefix) == want && strings.HasPrefix(r.Name, tagRefPrefix) {
				return want, r.SHA
			}
		}
	}
	return "", ""
}

func (n *Node) GetDependencies() []any { return n.deps }

func (n *Node) CreateSkippedOutput(reason string, input dag_impl.Input) *Output {
	return NewOutput(executiondag.StatusSkipped, reason, "", "", input)
}

func (n *Node) Kind() string { return "fetch" }

func (n *Node) Read(ctx context.Context, input dag_impl.Input) (*Output, error) {
	logger := ctxutil.GetLogger(ctx)

	output, err := dag_impl.ReadOutput[*Output](ctx, input)
	if err != nil {
		// Nothing persisted (e.g. the fetch run had no gitHead and skipped this
		// node). Treat as skipped so the published detector falls back to HEAD.
		return NewOutput(executiondag.StatusSkipped, "no published clone available", "", "", input), nil
	}

	if output.GetStatus() != executiondag.StatusSuccess {
		return output, nil
	}

	repoPath := git_clone_content.RepoWorkPath(ctx, input, repoDirName)
	if _, statErr := os.Stat(repoPath); statErr != nil {
		return NewOutput(executiondag.StatusSkipped, "published clone directory not found", "", "", input), nil
	}
	output.RepoPath = repoPath

	logger.Debug("verified cached published clone",
		zap.String("path", repoPath), zap.String("commit", output.Commit))
	return output, nil
}

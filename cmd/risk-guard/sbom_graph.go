package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/depsgraph"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem"
	"github.com/Risk-Guard/oss-risk-guard/src/language/unsupported"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	"github.com/fatih/color"
	"go.uber.org/zap"
)

// supportRequestURL is where users can ask for an unsupported package manager to
// be parsed. Printed beneath the unsupported-manifest inventory.
const supportRequestURL = "https://github.com/Risk-Guard/oss-risk-guard/issues"

// sourceKey mirrors dag_impl.NewSourceInputWithOverrides's analysis-identifier
// formatting so the rootKey is consistent across local CLI commands.
func sourceKey(sourceURL string) string {
	if _, after, found := strings.Cut(sourceURL, "://"); found {
		return "source/" + after
	}
	return "source/" + sourceURL
}

// manifestReport records, per detected manifest, how it was parsed: whether a
// lockfile backed it (full transitive tree) or it fell back to manifest-declared
// direct deps, the dependency counts it contributed, and any parse error. It
// drives the per-manifest progress output. Counts are per-manifest and may
// overlap across manifests (a shared dep is counted under each), so they do not
// necessarily sum to the repo-wide unique-package total.
type manifestReport struct {
	Ecosystem       string
	PackageManager  *string
	Paths           []string
	Lockfile        *string
	UsedLockfile    bool
	DirectCount     int
	TransitiveCount int
	Err             error
}

func collectEdges(rootKey string, manifests []models.DetectedManifest, repoRoot string) ([]models.DepsTreeEdge, []manifestReport) {
	var edges []models.DepsTreeEdge
	reports := make([]manifestReport, 0, len(manifests))

	for _, m := range manifests {
		rep := manifestReport{
			Ecosystem:      m.Ecosystem,
			PackageManager: m.PackageManager,
			Paths:          m.Paths,
			Lockfile:       m.Lockfile,
		}

		result, err := ecosystem.ParseManifest(m, repoRoot)
		if err != nil {
			rep.Err = err
			reports = append(reports, rep)
			continue
		}

		if len(result.LockfileDependencies) > 0 {
			rep.UsedLockfile = true
			children := make(map[string]bool)
			direct := make(map[string]bool)
			for _, e := range result.LockfileDependencies {
				parent := e.ParentKey
				if parent == "" {
					parent = rootKey
				}
				children[e.ChildKey] = true
				if parent == rootKey {
					direct[e.ChildKey] = true
				}
				edges = append(edges, models.DepsTreeEdge{
					ParentKey: parent,
					ChildKey:  e.ChildKey,
					Ecosystem: e.Ecosystem,
					Dev:       e.Dev,
					Location:  e.Location,
				})
			}
			rep.DirectCount = len(direct)
			rep.TransitiveCount = len(children) - len(direct)
			reports = append(reports, rep)
			continue
		}

		direct := make(map[string]bool)
		for _, d := range result.Dependencies {
			if d.AnalysisIdentifier == "" {
				continue
			}
			direct[d.AnalysisIdentifier] = true
			edges = append(edges, models.DepsTreeEdge{
				ParentKey: rootKey,
				ChildKey:  d.AnalysisIdentifier,
				Ecosystem: m.Ecosystem,
				Dev:       d.Dev,
				Location:  d.Location,
			})
		}
		rep.DirectCount = len(direct)
		reports = append(reports, rep)
	}
	return edges, reports
}

// printManifestReports lists detected manifests grouped by ecosystem, each with
// its direct-dependency count and a nested lockfile line when a lockfile added
// transitives. The intent is a calm inventory: "no lockfile" is the normal state
// for ecosystems like pip and is left uncolored, while only genuine problems — a
// parse failure or a detected-but-unparsed lockfile — are highlighted in yellow.
func printManifestReports(logger *zap.Logger, reports []manifestReport) {
	if len(reports) == 0 {
		fmt.Fprintf(os.Stderr, "  %s\n", color.HiBlackString("no supported manifests detected"))
		return
	}

	order := make([]string, 0)
	byEco := make(map[string][]manifestReport)
	for _, r := range reports {
		if _, ok := byEco[r.Ecosystem]; !ok {
			order = append(order, r.Ecosystem)
		}
		byEco[r.Ecosystem] = append(byEco[r.Ecosystem], r)
		if r.Err != nil {
			logger.Warn("manifest parse failed",
				zap.String("ecosystem", r.Ecosystem),
				zap.Strings("paths", r.Paths),
				zap.Error(r.Err))
		}
	}

	bold := color.New(color.Bold).FprintfFunc()
	for _, eco := range order {
		fmt.Fprintln(os.Stderr)
		bold(os.Stderr, "  %s\n", eco)
		for _, r := range byEco[eco] {
			printManifestLine(r)
		}
	}
}

// printManifestLine renders one manifest: its path(s) and direct-dep count
// (prefixed with the package manager when it differs from the ecosystem), then a
// nested lockfile line — dim "(+N transitive)" when the lockfile was parsed, or a
// yellow "not parsed" note when it was detected but unsupported.
func printManifestLine(r manifestReport) {
	paths := strings.Join(r.Paths, ", ")

	if r.Err != nil {
		fmt.Fprintf(os.Stderr, "    %s %s\n", paths, color.YellowString("(⚠ parse failed: %v)", r.Err))
		return
	}

	meta := fmt.Sprintf("%d direct", r.DirectCount)
	if pm := r.PackageManager; pm != nil && *pm != "" && *pm != r.Ecosystem {
		meta = *pm + " · " + meta
	}
	fmt.Fprintf(os.Stderr, "    %s %s\n", paths, color.HiBlackString("(%s)", meta))

	if r.Lockfile == nil {
		return
	}
	lock := filepath.Base(*r.Lockfile)
	if r.UsedLockfile {
		fmt.Fprintf(os.Stderr, "      %s\n", color.HiBlackString("↳ %s (+%d transitive)", lock, r.TransitiveCount))
	} else {
		fmt.Fprintf(os.Stderr, "      %s\n", color.YellowString("↳ %s not parsed; direct deps only", lock))
	}
}

// printUnsupportedManifests lists the manifest files whose package manager Risk
// Guard cannot parse for dependencies — the same set behind the
// SOURCE_UNSUPPORTED_MANIFEST_FILE finding — so the inventory shows what the SBOM
// could not reach, with a link to request support. Each line mirrors that
// check's evidence format: "<path> (<package manager>[, OSV ecosystem: <eco>])".
func printUnsupportedManifests(manifests []unsupported.DetectedManifest) {
	if len(manifests) == 0 {
		return
	}
	sorted := make([]unsupported.DetectedManifest, len(manifests))
	copy(sorted, manifests)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].RelPath < sorted[j].RelPath })

	orange := color.New(color.FgYellow, color.Bold).FprintfFunc()
	fmt.Fprintln(os.Stderr)
	orange(os.Stderr, "unsupported:\n")
	for _, m := range sorted {
		osvInfo := ""
		if m.OSVEcosystem != "" {
			osvInfo = ", OSV ecosystem: " + m.OSVEcosystem
		}
		fmt.Fprintf(os.Stderr, "  %s %s\n", m.RelPath, color.HiBlackString("(%s%s)", m.PackageManager, osvInfo))
	}
	fmt.Fprintf(os.Stderr, "\n  %s %s\n",
		color.HiBlackString("file a support request"), color.CyanString(supportRequestURL))
}

// countPackages counts SBOM nodes that resolved to an actual package, excluding
// the synthetic root node (which has no ecosystem). This is the package total
// the SBOM enumerates, as distinct from the raw node count that includes root.
func countPackages(nodes []depsgraph.SBOMNode) int {
	n := 0
	for _, node := range nodes {
		if node.Ecosystem != nil {
			n++
		}
	}
	return n
}

func buildSBOMNodes(rootKey string, edges []models.DepsTreeEdge) []depsgraph.SBOMNode {
	depsByParent := make(map[string][]string, len(edges))
	depsSeen := make(map[string]map[string]bool, len(edges))
	directLocation := make(map[string]*models.LocationInfo)
	seen := make(map[string]bool, len(edges)*2)
	seen[rootKey] = true

	for _, e := range edges {
		if depsSeen[e.ParentKey] == nil {
			depsSeen[e.ParentKey] = make(map[string]bool)
		}
		if !depsSeen[e.ParentKey][e.ChildKey] {
			depsSeen[e.ParentKey][e.ChildKey] = true
			depsByParent[e.ParentKey] = append(depsByParent[e.ParentKey], e.ChildKey)
		}
		seen[e.ParentKey] = true
		seen[e.ChildKey] = true
		if e.ParentKey == rootKey && e.Location != nil {
			if _, exists := directLocation[e.ChildKey]; !exists {
				directLocation[e.ChildKey] = e.Location
			}
		}
	}

	nodes := make([]depsgraph.SBOMNode, 0, len(seen))
	for key := range seen {
		node := depsgraph.SBOMNode{
			Key:      key,
			Deps:     depsByParent[key],
			Location: directLocation[key],
		}
		if eco, name, version := parseKeyIdentity(key); eco != "" {
			node.Ecosystem = &eco
			node.PackageName = &name
			if version != "" {
				node.PackageVersion = &version
			}
		}
		nodes = append(nodes, node)
	}
	return nodes
}

// parseKeyIdentity extracts ecosystem, name, and version from an analysis key
// of the form "package/{eco}/{name}" or "package/{eco}/{name}?version={ver}".
// Returns empty strings for non-package keys (e.g. the "source/..." rootKey).
func parseKeyIdentity(key string) (ecosystem, name, version string) {
	path, query, hasQuery := strings.Cut(key, "?")
	if hasQuery {
		for param := range strings.SplitSeq(query, "&") {
			if v, ok := strings.CutPrefix(param, "version="); ok {
				if decoded, err := url.QueryUnescape(v); err == nil {
					version = decoded
				} else {
					version = v
				}
			}
		}
	}
	rest, found := strings.CutPrefix(path, "package/")
	if !found {
		return "", "", ""
	}
	ecosystem, name, found = strings.Cut(rest, "/")
	if !found || ecosystem == "" || name == "" {
		return "", "", ""
	}
	return ecosystem, name, version
}

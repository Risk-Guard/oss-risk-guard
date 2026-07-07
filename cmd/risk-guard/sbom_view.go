package main

import (
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var sbomViewMaxDepth int

var sbomViewCmd = &cobra.Command{
	Use:   "view <sbom-file>",
	Short: "Render a saved SBOM (SPDX or CycloneDX) as a nested dependency tree",
	Long: `Read an SBOM JSON file produced by 'sbom' (or the pipeline's --sbom-out) and
print a nested dependency tree, npm-ls style: the format and spec version, the
generating tool, then the root component's direct dependencies grouped by
ecosystem (npm, pypi, …), each expanded into its own subtree indented by depth
and annotated with its version and (for direct deps) manifest provenance.

The tree follows the dependency graph recorded in the SBOM, so how deep it goes
depends on how much of the transitive tree the generating parser captured. A
package already expanded elsewhere is shown once and marked "(deduped)".

Use --max-depth to limit how deep the tree is walked: --max-depth 1 shows only
direct dependencies, --max-depth 2 adds their children, and so on. The default
(0) walks the full recorded tree. Packages whose children are hidden by the
limit are marked "(+N deps)".

The format (SPDX 3.0.1 or CycloneDX 1.6) is detected from the file contents, so
no --format flag is needed.

Examples:
  risk-guard sbom view sbom.spdx.json
  risk-guard sbom view sbom.cdx.json --max-depth 1
  risk-guard sbom view sbom.cdx.json --max-depth 3`,
	Args: cobra.ExactArgs(1),
	RunE: runSBOMView,
}

func init() {
	sbomViewCmd.Flags().IntVar(&sbomViewMaxDepth, "max-depth", 0, "Maximum dependency depth to display (1 = direct deps only; 0 = the full recorded tree)")
	sbomCmd.AddCommand(sbomViewCmd)
}

func runSBOMView(_ *cobra.Command, args []string) error {
	if sbomViewMaxDepth < 0 {
		return fmt.Errorf("--max-depth must be >= 0")
	}
	path := args[0]
	raw, err := os.ReadFile(path) //nolint:gosec // path is a user-provided argument
	if err != nil {
		return fmt.Errorf("reading SBOM: %w", err)
	}
	summary, err := sbom.ReadSummary(raw)
	if err != nil {
		return fmt.Errorf("parsing SBOM %s: %w", path, err)
	}
	printSBOMSummary(os.Stdout, path, summary, sbomViewMaxDepth)
	return nil
}

// printSBOMSummary renders a parsed SBOM to w: a header block of metadata
// followed by the dependency tree rooted at the SBOM's root component.
func printSBOMSummary(w io.Writer, path string, summary *sbom.Summary, maxDepth int) {
	ew := &sbomWriter{w: w}
	bold := color.New(color.Bold).SprintfFunc()

	ew.printf("%s\n", bold(path))
	specVer := summary.SpecVersion
	if specVer != "" {
		specVer = " " + specVer
	}
	ew.printf("  %s %s\n", color.HiBlackString("Format:  "), summary.Format+specVer)
	if summary.Tool != "" {
		ew.printf("  %s %s\n", color.HiBlackString("Tool:    "), summary.Tool)
	}
	ew.printf("  %s %s\n", color.HiBlackString("Packages:"), color.HiBlackString("%d", len(summary.Packages)))

	rootName := summary.RootName
	if rootName == "" {
		rootName = "(root)"
	}
	ew.printf("\n%s\n", bold(rootName))

	tree := &sbomTree{
		ew:       ew,
		byKey:    make(map[string]sbom.Package, len(summary.Packages)),
		seen:     make(map[string]bool),
		maxDepth: maxDepth,
	}
	for _, p := range summary.Packages {
		tree.byKey[p.Key] = p
	}

	children := tree.sortedChildren(summary.RootDeps)
	if len(children) == 0 {
		ew.printf("%s\n", color.HiBlackString("(no dependencies)"))
		return
	}

	// The root's direct dependencies are grouped by ecosystem so npm, pypi, … each
	// get a header; every dependency's own subtree still nests by depth beneath it.
	// (Transitives keep their parent, regardless of ecosystem.)
	groups, ecoOrder := groupByEcosystem(tree, children)
	for _, eco := range ecoOrder {
		ew.printf("\n%s\n", bold(eco))
		ks := groups[eco]
		for i, key := range ks {
			tree.walk(key, "", i == len(ks)-1, 1)
		}
	}
}

// groupByEcosystem buckets the (already deduped, label-sorted) direct-dependency
// keys by ecosystem, returning the buckets and the ecosystem names in
// alphabetical order. Within a bucket the incoming order is preserved.
func groupByEcosystem(tree *sbomTree, keys []string) (map[string][]string, []string) {
	groups := make(map[string][]string)
	var order []string
	for _, k := range keys {
		eco := sbomEcoLabel("")
		if p, ok := tree.byKey[k]; ok {
			eco = sbomEcoLabel(p.Ecosystem)
		}
		if _, seen := groups[eco]; !seen {
			order = append(order, eco)
		}
		groups[eco] = append(groups[eco], k)
	}
	sort.Strings(order)
	return groups, order
}

// sbomTree carries the shared state for a depth-first tree walk: the package
// index, the set of already-expanded keys (for deduping shared subtrees), and
// the depth limit.
type sbomTree struct {
	ew       *sbomWriter
	byKey    map[string]sbom.Package
	seen     map[string]bool
	maxDepth int
}

// walk prints one node and, unless capped by depth or already expanded,
// recurses into its dependencies. prefix is the indentation carried from
// ancestors; last marks the final sibling so the connector and the child prefix
// switch from "├──/│" to "└──/spaces". depth is 1 for the root's direct deps.
func (t *sbomTree) walk(key, prefix string, last bool, depth int) {
	connector, childPrefix := "├── ", prefix+"│   "
	if last {
		connector, childPrefix = "└── ", prefix+"    "
	}

	pkg, known := t.byKey[key]
	label := sbomTreeLabel(key, pkg, known)
	if loc := formatSBOMLocation(pkg.Location); known && loc != "" {
		label += "  " + color.HiBlackString(loc)
	}

	children := t.sortedChildren(pkg.Deps)

	switch {
	case len(children) == 0:
		t.ew.printf("%s%s%s\n", prefix, connector, label)
	case t.maxDepth > 0 && depth >= t.maxDepth:
		// Depth limit reached: show the node but surface the hidden children.
		t.ew.printf("%s%s%s %s\n", prefix, connector, label, color.HiBlackString("(+%d deps)", len(children)))
	case t.seen[key]:
		// Already expanded under another parent; don't repeat the subtree.
		t.ew.printf("%s%s%s %s\n", prefix, connector, label, color.HiBlackString("(deduped)"))
	default:
		t.seen[key] = true
		t.ew.printf("%s%s%s\n", prefix, connector, label)
		for i, ck := range children {
			t.walk(ck, childPrefix, i == len(children)-1, depth+1)
		}
	}
}

// sortedChildren dedupes a list of child keys and orders them by display label
// (name@version), so sibling ordering is deterministic regardless of the order
// the SBOM listed edges.
func (t *sbomTree) sortedChildren(keys []string) []string {
	seen := make(map[string]bool, len(keys))
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return t.sortKey(out[i]) < t.sortKey(out[j]) })
	return out
}

func (t *sbomTree) sortKey(key string) string {
	if p, ok := t.byKey[key]; ok && p.Name != "" {
		return sbomPackageLabel(p)
	}
	return key
}

// sbomWriter wraps an io.Writer and remembers the first write error so the
// printer can stream to it without checking every call; the terminal writer
// (os.Stdout) does not fail in practice, but a broken pipe is recorded.
type sbomWriter struct {
	w   io.Writer
	err error
}

func (s *sbomWriter) printf(format string, a ...any) {
	if s.err != nil {
		return
	}
	_, s.err = fmt.Fprintf(s.w, format, a...)
}

// sbomTreeLabel renders a tree node as "name@version" (or "name"), falling back
// to the raw analysis key when the package is missing from the index or has no
// name.
func sbomTreeLabel(key string, pkg sbom.Package, known bool) string {
	if !known || pkg.Name == "" {
		return key
	}
	return sbomPackageLabel(pkg)
}

// sbomEcoLabel maps an empty ecosystem to the "unknown" bucket used for the
// top-level ecosystem grouping.
func sbomEcoLabel(eco string) string {
	if eco == "" {
		return "unknown"
	}
	return eco
}

// sbomPackageLabel renders a package as "name@version", or just "name" when the
// SBOM recorded no version.
func sbomPackageLabel(p sbom.Package) string {
	if p.Version != "" {
		return p.Name + "@" + p.Version
	}
	return p.Name
}

// formatSBOMLocation renders a package's manifest provenance as "file" or
// "file:line", or "" when the SBOM carried no location.
func formatSBOMLocation(loc *models.LocationInfo) string {
	if loc == nil || loc.File == nil || *loc.File == "" {
		return ""
	}
	if loc.LineNumber != nil && *loc.LineNumber > 0 {
		return fmt.Sprintf("%s:%d", *loc.File, *loc.LineNumber)
	}
	return *loc.File
}

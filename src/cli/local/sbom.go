package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/depsgraph"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/def"
	"github.com/Risk-Guard/oss-risk-guard/src/git"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom/cdx16"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom/spdx30"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"github.com/Risk-Guard/oss-risk-guard/src/package_detection"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

const (
	sbomFormatSPDX      = "spdx"
	sbomFormatCycloneDX = "cyclonedx"
	sbomToolName        = "risk-guard"
)

var (
	sbomFormat string
	sbomOutput string
)

var sbomCmd = &cobra.Command{
	Use:   "sbom <path>",
	Short: "Generate an SBOM (SPDX or CycloneDX) for a local git repository",
	Long: `Generate a Software Bill of Materials for a local on-disk git repository.

Reads lockfiles and manifests on disk and emits an SBOM. Fully offline: no
registry calls, no artifact downloads, no scoring checks.

Coverage of the transitive dep tree depends on the lockfile parser for each
ecosystem. Ecosystems with a working lockfile parser (npm/yarn/pnpm/bun, uv,
bundler) get full transitives; ecosystems without one (poetry, pipenv, pdm)
get manifest-declared direct deps only.

Examples:
  risk-guard-local sbom . --format spdx
  risk-guard-local sbom . --format cyclonedx --output sbom.cdx.json`,
	Args: cobra.ExactArgs(1),
	RunE: runSBOM,
}

func init() {
	sbomCmd.Flags().StringVar(&sbomFormat, "format", sbomFormatSPDX, "SBOM format: spdx or cyclonedx")
	sbomCmd.Flags().StringVarP(&sbomOutput, "output", "o", "-", "Output file path, or - for stdout")
	rootCmd.AddCommand(sbomCmd)
}

func runSBOM(command *cobra.Command, args []string) error {
	switch sbomFormat {
	case sbomFormatSPDX, sbomFormatCycloneDX:
	default:
		return fmt.Errorf("unsupported --format %q (want %q or %q)", sbomFormat, sbomFormatSPDX, sbomFormatCycloneDX)
	}

	logger := ctxutil.GetLogger(command.Context())

	repoPath, err := git.ValidateGitRepo(args[0])
	if err != nil {
		return fmt.Errorf("invalid git repository: %w", err)
	}

	rootKey := sourceKey(repoPath)

	manifests, err := package_detection.DetectPackages(repoPath, def.All())
	if err != nil {
		return fmt.Errorf("detecting packages: %w", err)
	}
	logger.Info("detected manifests", zap.Int("count", len(manifests)))

	edges, parseErrs := collectEdges(rootKey, manifests, repoPath)
	for _, pe := range parseErrs {
		logger.Warn("manifest parse failed",
			zap.String("ecosystem", pe.Ecosystem),
			zap.Strings("paths", pe.Paths),
			zap.Error(pe.Err))
	}

	nodes := buildSBOMNodes(rootKey, edges)
	logger.Info("collected SBOM nodes", zap.Int("count", len(nodes)))

	data, err := buildSBOMJSON(sbomFormat, rootKey, nodes)
	if err != nil {
		return err
	}

	if err := writeSBOMOutput(sbomOutput, data); err != nil {
		return err
	}
	if sbomOutput != "-" {
		logger.Info("wrote SBOM", zap.String("path", sbomOutput), zap.String("format", sbomFormat))
	}
	return nil
}

// sourceKey mirrors dag_impl.NewSourceInputWithOverrides's analysis-identifier
// formatting so the rootKey is consistent across local CLI commands.
func sourceKey(sourceURL string) string {
	if _, after, found := strings.Cut(sourceURL, "://"); found {
		return "source/" + after
	}
	return "source/" + sourceURL
}

type manifestParseErr struct {
	Ecosystem string
	Paths     []string
	Err       error
}

func collectEdges(rootKey string, manifests []models.DetectedManifest, repoRoot string) ([]models.DepsTreeEdge, []manifestParseErr) {
	var edges []models.DepsTreeEdge
	var parseErrs []manifestParseErr

	for _, m := range manifests {
		result, err := ecosystem.ParseManifest(m, repoRoot)
		if err != nil {
			parseErrs = append(parseErrs, manifestParseErr{Ecosystem: m.Ecosystem, Paths: m.Paths, Err: err})
			continue
		}

		if len(result.LockfileDependencies) > 0 {
			for _, e := range result.LockfileDependencies {
				parent := e.ParentKey
				if parent == "" {
					parent = rootKey
				}
				edges = append(edges, models.DepsTreeEdge{
					ParentKey: parent,
					ChildKey:  e.ChildKey,
					Ecosystem: e.Ecosystem,
					Dev:       e.Dev,
					Location:  e.Location,
				})
			}
			continue
		}

		for _, d := range result.Dependencies {
			if d.AnalysisIdentifier == "" {
				continue
			}
			edges = append(edges, models.DepsTreeEdge{
				ParentKey: rootKey,
				ChildKey:  d.AnalysisIdentifier,
				Ecosystem: m.Ecosystem,
				Dev:       d.Dev,
				Location:  d.Location,
			})
		}
	}
	return edges, parseErrs
}

func buildSBOMNodes(rootKey string, edges []models.DepsTreeEdge) []depsgraph.SBOMNode {
	depsByParent := make(map[string][]string, len(edges))
	seen := make(map[string]bool, len(edges)*2)
	seen[rootKey] = true

	for _, e := range edges {
		depsByParent[e.ParentKey] = append(depsByParent[e.ParentKey], e.ChildKey)
		seen[e.ParentKey] = true
		seen[e.ChildKey] = true
	}

	nodes := make([]depsgraph.SBOMNode, 0, len(seen))
	for key := range seen {
		node := depsgraph.SBOMNode{
			Key:  key,
			Deps: depsByParent[key],
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

func buildSBOMJSON(format, rootKey string, nodes []depsgraph.SBOMNode) ([]byte, error) {
	switch format {
	case sbomFormatSPDX:
		doc, err := spdx30.NewBuilder(rootKey, nodes, sbomToolName).Build()
		if err != nil {
			return nil, fmt.Errorf("building SPDX document: %w", err)
		}
		return json.MarshalIndent(doc, "", "  ")
	case sbomFormatCycloneDX:
		bom, err := cdx16.NewBuilder(rootKey, nodes, sbomToolName).Build()
		if err != nil {
			return nil, fmt.Errorf("building CycloneDX BOM: %w", err)
		}
		return json.MarshalIndent(bom, "", "  ")
	default:
		return nil, fmt.Errorf("unsupported format %q", format)
	}
}

func writeSBOMOutput(path string, data []byte) error {
	if path == "-" {
		_, err := os.Stdout.Write(append(data, '\n'))
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing SBOM: %w", err)
	}
	return nil
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/ctxutil"
	"github.com/Risk-Guard/oss-risk-guard/src/depsgraph"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/def"
	"github.com/Risk-Guard/oss-risk-guard/src/language/unsupported"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom/cdx16"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom/spdx30"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
	"github.com/Risk-Guard/oss-risk-guard/src/package_detection"
	"github.com/Risk-Guard/oss-risk-guard/src/riskguardignore"

	"github.com/fatih/color"
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
ecosystem. Ecosystems with a working lockfile parser (npm, uv) get full
transitives; ecosystems without one (yarn/pnpm/bun, bundler, poetry, pipenv,
pdm) get manifest-declared direct deps only.

Writes to sbom.spdx.json (or sbom.cdx.json for CycloneDX) in the current
directory unless --output is set (use --output - for stdout).

Examples:
  risk-guard sbom .
  risk-guard sbom . --format cyclonedx --output sbom.cdx.json
  risk-guard sbom . --format spdx --output -`,
	Args: cobra.ExactArgs(1),
	RunE: runSBOM,
}

func init() {
	sbomCmd.Flags().StringVar(&sbomFormat, "format", "", "SBOM format: spdx or cyclonedx (inferred from --output extension when unset)")
	sbomCmd.Flags().StringVarP(&sbomOutput, "output", "o", "", "Output file path, or - for stdout (default: sbom.spdx.json / sbom.cdx.json)")
	rootCmd.AddCommand(sbomCmd)
}

func runSBOM(command *cobra.Command, args []string) error {
	logger := ctxutil.GetLogger(command.Context())

	format := sbomFormat
	if format == "" {
		if sbomOutput != "" {
			format = inferSBOMFormat(sbomOutput)
		} else {
			format = sbomFormatSPDX
		}
		logger.Debug("inferred SBOM format",
			zap.String("format", format), zap.String("output", sbomOutput))
	}

	output := sbomOutput
	if output == "" {
		output = defaultSBOMFilename(format)
	}

	data, err := buildSBOMBytes(command.Context(), args[0], format)
	if err != nil {
		return err
	}

	if err := writeSBOMOutput(output, data); err != nil {
		return err
	}
	if output != "-" {
		logger.Info("wrote SBOM",
			zap.String("path", output),
			zap.String("format", format))
	}
	return nil
}

// defaultSBOMFilename returns the output filename used when --output is omitted.
// It uses the conventional double-extension for each format (.spdx.json,
// .cdx.json) so the name round-trips through inferSBOMFormat and matches the
// examples in the command help.
func defaultSBOMFilename(format string) string {
	switch format {
	case sbomFormatCycloneDX:
		return "sbom.cdx.json"
	default:
		return "sbom.spdx.json"
	}
}

// inferSBOMFormat guesses the SBOM format from an output filename, using the
// conventional double-extensions each spec recommends (.spdx.json, .cdx.json,
// .bom.json). Falls back to spdx when the name carries no recognizable hint.
func inferSBOMFormat(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, ".cdx.") || strings.HasSuffix(lower, ".cdx") || strings.Contains(lower, ".bom."):
		return sbomFormatCycloneDX
	case strings.Contains(lower, ".spdx.") || strings.HasSuffix(lower, ".spdx"):
		return sbomFormatSPDX
	default:
		return sbomFormatSPDX
	}
}

// buildSBOMBytes runs manifest detection on path and returns the SBOM as JSON
// bytes in the requested format ("spdx" or "cyclonedx"). It performs no disk I/O
// on the output. Validates that path is an existing directory (via
// resolveScanPath); it need not be a git repo.
func buildSBOMBytes(ctx context.Context, path, format string) ([]byte, error) {
	data, _, err := buildSBOMBytesWithManifests(ctx, path, format)
	return data, err
}

// buildSBOMBytesWithManifests is buildSBOMBytes plus the post-.riskguardignore
// list of detected manifests, so callers (init) can offer them for further
// exclusion without re-walking the tree. The manifests are the ones that
// actually contributed to the SBOM (already filtered through filterIgnoredManifests).
func buildSBOMBytesWithManifests(ctx context.Context, path, format string) ([]byte, []models.DetectedManifest, error) {
	switch format {
	case sbomFormatSPDX, sbomFormatCycloneDX:
	default:
		return nil, nil, fmt.Errorf("unsupported sbom format %q (want %q or %q)", format, sbomFormatSPDX, sbomFormatCycloneDX)
	}

	logger := ctxutil.GetLogger(ctx)
	bold := color.New(color.Bold).FprintfFunc()
	bold(os.Stderr, "Building SBOM (%s)…\n", format)

	repoPath, err := resolveScanPath(path)
	if err != nil {
		return nil, nil, fmt.Errorf("resolving source path: %w", err)
	}

	rootKey := sourceKey(repoPath)

	manifests, err := package_detection.DetectPackages(repoPath, def.All())
	if err != nil {
		return nil, nil, fmt.Errorf("detecting packages: %w", err)
	}
	manifests = filterIgnoredManifests(ctx, repoPath, manifests)
	logger.Info("detected manifests", zap.Int("count", len(manifests)))

	edges, reports := collectEdges(rootKey, manifests, repoPath)
	printManifestReports(logger, reports)

	nodes := buildSBOMNodes(rootKey, edges)
	logger.Info("collected SBOM nodes", zap.Int("count", len(nodes)))
	fmt.Fprintf(os.Stderr, "\n  %s\n", color.HiBlackString("%d unique packages", countPackages(nodes)))

	// Surface the manifests the SBOM could not reach (CMake, Docker, Gradle, …) —
	// the set behind SOURCE_UNSUPPORTED_MANIFEST_FILE — so they are visible here,
	// not just counted in the finding. Unfiltered (matching that check) so the
	// list reconciles with it.
	if unsup, derr := unsupported.DetectUnsupportedManifests(repoPath); derr != nil {
		logger.Warn("detecting unsupported manifests", zap.Error(derr))
	} else {
		printUnsupportedManifests(unsup)
	}

	data, err := buildSBOMJSON(format, rootKey, nodes)
	if err != nil {
		return nil, nil, err
	}
	return data, manifests, nil
}

// filterIgnoredManifests drops manifests that live entirely under
// .riskguardignore'd paths, so dependencies declared in excluded directories
// (e.g. vendored third_party/ submodules) are not enumerated or audited. It
// uses the same matcher as the source-file ignore path, and reports how many
// manifests it excluded rather than dropping them silently.
func filterIgnoredManifests(ctx context.Context, repoPath string, manifests []models.DetectedManifest) []models.DetectedManifest {
	logger := ctxutil.GetLogger(ctx)
	matcher, err := riskguardignore.NewMatcher(repoPath)
	if err != nil {
		logger.Warn("reading .riskguardignore; auditing all manifests", zap.Error(err))
		return manifests
	}
	if matcher.Empty() {
		return manifests
	}

	kept := manifests[:0]
	dropped := 0
	for _, m := range manifests {
		if manifestIgnored(matcher, m) {
			dropped++
			logger.Debug("excluded manifest via .riskguardignore", zap.Strings("paths", m.Paths))
			continue
		}
		kept = append(kept, m)
	}
	if dropped > 0 {
		fmt.Fprintf(os.Stderr, "  %s\n", color.HiBlackString("excluded %d manifest(s) via .riskguardignore", dropped))
	}
	return kept
}

// manifestIgnored reports whether every file in a manifest is ignored. A
// manifest groups files that define one package (e.g. pyproject.toml + setup.py
// in the same dir), so it is excluded only when all of them are ignored.
func manifestIgnored(matcher *riskguardignore.Matcher, m models.DetectedManifest) bool {
	if len(m.Paths) == 0 {
		return false
	}
	for _, p := range m.Paths {
		if !matcher.Match(p) {
			return false
		}
	}
	return true
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

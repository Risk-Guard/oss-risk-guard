package npm

import (
	"os"
	"path/filepath"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/npm/package_manager/bun"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/npm/package_manager/pnpm"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/npm/package_manager/yarn"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/pathutil"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	innernpm "github.com/Risk-Guard/oss-risk-guard/src/ecosystem/npm/package_manager/npm"
)

func ParseManifest(detected models.DetectedManifest, repoRoot string) (*models.ManifestResult, error) {
	result := &models.ManifestResult{DetectedManifest: detected}

	if len(detected.Paths) == 0 {
		parseErr := "no manifest path provided"
		result.ParseError = &parseErr
		return result, nil
	}

	manifestPath := pathutil.ResolveManifestPath(detected.Paths[0], repoRoot)

	// #nosec G304 -- path comes from validated detection
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		parseErr := "failed to read file: " + err.Error()
		result.ParseError = &parseErr
		return result, nil
	}

	deps, pkg, err := innernpm.ParsePackageJSON(string(content), detected.Paths[0])
	if err != nil {
		parseErr := "failed to parse JSON: " + err.Error()
		result.ParseError = &parseErr
		return result, nil
	}

	if pkg.Name != "" {
		result.Name = &pkg.Name
	}
	result.Private = bool(pkg.Private)
	result.Dependencies = deps
	result.InstallScripts = innernpm.ExtractInstallScripts(*pkg)

	if detected.Lockfile != nil {
		edges, err := parseLockfile(*detected.Lockfile, repoRoot)
		if err != nil {
			parseErr := "failed to parse lockfile: " + err.Error()
			result.ParseError = &parseErr
			return result, nil
		}
		result.LockfileDependencies = edges
	}

	return result, nil
}

func parseLockfile(lockfilePath, repoRoot string) ([]models.DepsTreeEdge, error) {
	filename := filepath.Base(lockfilePath)
	fullPath := pathutil.ResolveManifestPath(lockfilePath, repoRoot)

	// #nosec G304 -- path comes from validated detection
	content, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, err
	}

	if innernpm.OwnsLockfile(filename) {
		return innernpm.ParseLockfile(content)
	}
	if yarn.OwnsLockfile(filename) {
		return yarn.ParseLockfile(content)
	}
	if pnpm.OwnsLockfile(filename) {
		return pnpm.ParseLockfile(content)
	}
	if bun.OwnsLockfile(filename) {
		return bun.ParseLockfile(content)
	}

	return nil, nil
}

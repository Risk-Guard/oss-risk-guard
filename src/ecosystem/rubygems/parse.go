package rubygems

import (
	"fmt"
	"os"
	"path/filepath"
	"risk-guard/src/ecosystem/def"
	"risk-guard/src/ecosystem/pathutil"
	"risk-guard/src/ecosystem/rubygems/package_manager/bundler"
	"risk-guard/src/models"
	"risk-guard/src/parsers/ruby/gemfile"
	"risk-guard/src/parsers/ruby/gemspec"
	"strings"
)

func ParseManifest(detected models.DetectedManifest, repoRoot string) (*models.ManifestResult, error) {
	result := &models.ManifestResult{DetectedManifest: detected}

	if len(detected.Paths) == 0 {
		parseErr := "no manifest path provided"
		result.ParseError = &parseErr
		return result, nil
	}

	paths := sortManifestsByPriority(detected.Paths)
	for _, relPath := range paths {
		if err := parseFile(result, relPath, repoRoot); err != nil {
			return nil, err
		}
	}

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

	if bundler.OwnsLockfile(filename) {
		return bundler.ParseLockfile(content)
	}

	return nil, nil
}

func parseFile(result *models.ManifestResult, relPath, repoRoot string) error {
	manifestPath := pathutil.ResolveManifestPath(relPath, repoRoot)
	filename := filepath.Base(manifestPath)

	// #nosec G304 -- path comes from validated detection
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		parseErr := "failed to read file: " + err.Error()
		result.ParseError = &parseErr
		return nil
	}

	switch {
	case strings.HasSuffix(filename, ".gemspec"):
		nameResult := gemspec.Parse(manifestPath)
		if nameResult.Error == nil {
			def.ApplyNameResult(result, nameResult)
		} else {
			parseErr := "failed to parse gemspec name: " + nameResult.Error.Error()
			result.ParseError = &parseErr
		}

		deps, dynDeps, err := gemspec.ExtractDependencies(string(content), relPath)
		if err != nil {
			parseErr := "failed to parse dependencies: " + err.Error()
			result.ParseError = &parseErr
			return nil
		}
		result.Dependencies = append(result.Dependencies, deps...)
		result.DynamicDependencies = append(result.DynamicDependencies, dynDeps...)

	case filename == "Gemfile":
		deps, dynDeps, err := gemfile.ExtractDependencies(string(content), relPath)
		if err != nil {
			parseErr := "failed to parse: " + err.Error()
			result.ParseError = &parseErr
			return nil
		}
		result.Dependencies = append(result.Dependencies, deps...)
		result.DynamicDependencies = append(result.DynamicDependencies, dynDeps...)

	default:
		return fmt.Errorf("unsupported manifest type: %s", filename)
	}

	return nil
}

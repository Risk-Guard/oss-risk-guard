package pypi

import (
	"fmt"
	"os"
	"path/filepath"
	"risk-guard/src/ecosystem/def"
	"risk-guard/src/ecosystem/pathutil"
	"risk-guard/src/ecosystem/pypi/package_manager/pdm"
	"risk-guard/src/ecosystem/pypi/package_manager/pipenv"
	"risk-guard/src/ecosystem/pypi/package_manager/poetry"
	"risk-guard/src/ecosystem/pypi/package_manager/uv"
	"risk-guard/src/models"
	"risk-guard/src/parsers/python/pep508"
	"risk-guard/src/parsers/python/pyproject"
	"risk-guard/src/parsers/python/setup"
	"risk-guard/src/parsers/python/setupcfg"
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

	if poetry.OwnsLockfile(filename) {
		return poetry.ParseLockfile(content)
	}
	if pipenv.OwnsLockfile(filename) {
		return pipenv.ParseLockfile(content)
	}
	if pdm.OwnsLockfile(filename) {
		return pdm.ParseLockfile(content)
	}
	if uv.OwnsLockfile(filename) {
		return uv.ParseLockfile(content)
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

	switch filename {
	case "requirements.txt":
		parsed, err := pep508.ParseRequirementsTxt(string(content), relPath)
		if err != nil {
			parseErr := "failed to parse: " + err.Error()
			result.ParseError = &parseErr
			return nil
		}
		result.Dependencies = append(result.Dependencies, parsed...)

	case "pyproject.toml":
		nameResult := pyproject.ParseName(string(content))
		def.ApplyNameResult(result, nameResult)

		parsed, err := pyproject.Parse(string(content), relPath)
		if err != nil {
			parseErr := "failed to parse: " + err.Error()
			result.ParseError = &parseErr
			return nil
		}
		result.Dependencies = append(result.Dependencies, parsed...)

	case "setup.py":
		nameResult := setup.Parse(manifestPath)
		if nameResult.Error == nil {
			def.ApplyNameResult(result, nameResult)
		} else if result.Name == nil {
			parseErr := "failed to parse setup.py: " + nameResult.Error.Error()
			result.ParseError = &parseErr
		}

	case "setup.cfg":
		nameResult := setupcfg.ParseName(string(content))
		def.ApplyNameResult(result, nameResult)

	default:
		return fmt.Errorf("invalid filename for ParseManifest %s", filename)
	}

	return nil
}

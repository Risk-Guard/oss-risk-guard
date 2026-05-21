package uv

import (
	"fmt"

	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/def"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/lockfile"
	"github.com/Risk-Guard/oss-risk-guard/src/models"

	"github.com/BurntSushi/toml"

	pythonnormalize "github.com/Risk-Guard/oss-risk-guard/src/language/python/normalize"
)

const LockfileName = "uv.lock"

var Manager = def.NewPackageManager("uv", "pypi", LockfileName)

func DetectLockfile(manifestDir, repoRoot string) *string {
	return lockfile.Detect(manifestDir, repoRoot, LockfileName)
}

func OwnsLockfile(filename string) bool {
	return filename == LockfileName
}

type uvLockFile struct {
	Packages []uvPackage `toml:"package"`
}

type uvPackage struct {
	Name                 string                    `toml:"name"`
	Version              string                    `toml:"version"`
	Source               uvSource                  `toml:"source"`
	Dependencies         []uvDependency            `toml:"dependencies"`
	OptionalDependencies map[string][]uvDependency `toml:"optional-dependencies"`
	DevDependencies      map[string][]uvDependency `toml:"dev-dependencies"`
}

type uvSource struct {
	Virtual  string `toml:"virtual"`
	Editable string `toml:"editable"`
	Registry string `toml:"registry"`
}

type uvDependency struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

func isRootPackage(pkg uvPackage) bool {
	return pkg.Source.Virtual != "" || pkg.Source.Editable != ""
}

func makeKey(name, version string) string {
	normalized := pythonnormalize.NormalizePyPIName(name)
	if version == "" {
		return "package/pypi/" + normalized
	}
	return "package/pypi/" + normalized + "?version=" + version
}

func resolveVersion(name string, index map[string]uvPackage) string {
	normalized := pythonnormalize.NormalizePyPIName(name)
	if pkg, ok := index[normalized]; ok {
		return pkg.Version
	}
	return ""
}

func buildPackageIndex(packages []uvPackage) map[string]uvPackage {
	index := make(map[string]uvPackage, len(packages))
	for _, pkg := range packages {
		normalized := pythonnormalize.NormalizePyPIName(pkg.Name)
		index[normalized] = pkg
	}
	return index
}

func ParseLockfile(content []byte) ([]models.DepsTreeEdge, error) {
	if len(content) == 0 {
		return nil, fmt.Errorf("uv.lock file is empty")
	}

	var lf uvLockFile
	if err := toml.Unmarshal(content, &lf); err != nil {
		return nil, fmt.Errorf("parsing uv.lock: %w", err)
	}

	index := buildPackageIndex(lf.Packages)
	seen := make(map[string]struct{})
	var edges []models.DepsTreeEdge

	addEdge := func(parent, child string, dev bool) {
		key := parent + "|" + child
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			edges = append(edges, models.DepsTreeEdge{
				ParentKey: parent,
				ChildKey:  child,
				Ecosystem: "pypi",
				Dev:       dev,
			})
		}
	}

	for _, pkg := range lf.Packages {
		if isRootPackage(pkg) {
			for _, dep := range pkg.Dependencies {
				version := resolveVersion(dep.Name, index)
				addEdge("", makeKey(dep.Name, version), false)
			}
			for _, deps := range pkg.OptionalDependencies {
				for _, dep := range deps {
					version := resolveVersion(dep.Name, index)
					addEdge("", makeKey(dep.Name, version), false)
				}
			}
			for _, deps := range pkg.DevDependencies {
				for _, dep := range deps {
					version := resolveVersion(dep.Name, index)
					addEdge("", makeKey(dep.Name, version), true)
				}
			}
			continue
		}

		parentKey := makeKey(pkg.Name, pkg.Version)

		for _, dep := range pkg.Dependencies {
			version := resolveVersion(dep.Name, index)
			addEdge(parentKey, makeKey(dep.Name, version), false)
		}
		for _, deps := range pkg.OptionalDependencies {
			for _, dep := range deps {
				version := resolveVersion(dep.Name, index)
				addEdge(parentKey, makeKey(dep.Name, version), false)
			}
		}
		for _, deps := range pkg.DevDependencies {
			for _, dep := range deps {
				version := resolveVersion(dep.Name, index)
				addEdge(parentKey, makeKey(dep.Name, version), true)
			}
		}
	}

	lockfile.PropagateDevFlag(edges, "")
	return edges, nil
}

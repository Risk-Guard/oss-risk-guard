package npm

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/def"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/lockfile"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

const LockfileName = "package-lock.json"

var Manager = def.NewPackageManager("npm", "npm", LockfileName)

func DetectLockfile(manifestDir, repoRoot string) *string {
	return lockfile.Detect(manifestDir, repoRoot, LockfileName)
}

func OwnsLockfile(filename string) bool {
	return filename == LockfileName
}

type packageLockFile struct {
	LockfileVersion int                         `json:"lockfileVersion"`
	Packages        map[string]packageLockPkg   `json:"packages"`
	Dependencies    map[string]packageLockDepV1 `json:"dependencies"`
}

type packageLockPkg struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dev                  bool              `json:"dev"`
	Link                 bool              `json:"link"`
	Resolved             string            `json:"resolved"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

type packageLockDepV1 struct {
	Version      string                      `json:"version"`
	Dev          bool                        `json:"dev"`
	Dependencies map[string]packageLockDepV1 `json:"dependencies"`
}

func ParseLockfile(content []byte) ([]models.DepsTreeEdge, error) {
	var lf packageLockFile
	if err := json.Unmarshal(content, &lf); err != nil {
		return nil, fmt.Errorf("parsing package-lock.json: %w", err)
	}

	if lf.LockfileVersion >= 2 && lf.Packages != nil {
		return parsePackagesV2V3(lf.Packages)
	}

	if lf.LockfileVersion == 1 && lf.Dependencies != nil {
		return parseDependenciesV1(lf.Dependencies)
	}

	return nil, fmt.Errorf("unsupported package-lock.json: lockfileVersion=%d, has packages=%v, has dependencies=%v",
		lf.LockfileVersion, lf.Packages != nil, lf.Dependencies != nil)
}

func parsePackagesV2V3(packages map[string]packageLockPkg) ([]models.DepsTreeEdge, error) {
	if _, hasRoot := packages[""]; !hasRoot {
		return nil, nil
	}

	roots := findRoots(packages)
	seen := make(map[string]struct{})
	var edges []models.DepsTreeEdge

	addEdge := func(parent, child string, dev bool) {
		key := parent + "|" + child
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			edges = append(edges, models.DepsTreeEdge{
				ParentKey: parent,
				ChildKey:  child,
				Ecosystem: "npm",
				Dev:       dev,
			})
		}
	}

	for pkgPath, pkg := range packages {
		if pkgPath == "" || pkg.Link {
			continue
		}

		pkgName := extractName(pkgPath, pkg)
		if pkgName == "" {
			continue
		}

		childKey := makeKey(pkgName, pkg.Version)

		if isDirectDep(pkgPath, roots, packages) {
			addEdge("", childKey, pkg.Dev)
		}

		for depName := range pkg.Dependencies {
			if dep, ok := resolvePackageByName(pkgPath, depName, packages); ok {
				addEdge(childKey, makeKey(canonicalName(depName, dep), dep.Version), dep.Dev)
			}
		}
	}

	return edges, nil
}

func parseDependenciesV1(deps map[string]packageLockDepV1) ([]models.DepsTreeEdge, error) {
	var edges []models.DepsTreeEdge
	collectEdgesV1(deps, "", &edges)
	return edges, nil
}

func collectEdgesV1(deps map[string]packageLockDepV1, parentKey string, edges *[]models.DepsTreeEdge) {
	for name, dep := range deps {
		childKey := makeKey(name, dep.Version)
		edge := models.DepsTreeEdge{
			ParentKey: parentKey,
			ChildKey:  childKey,
			Ecosystem: "npm",
			Dev:       dep.Dev,
		}
		*edges = append(*edges, edge)

		if dep.Dependencies != nil {
			collectEdgesV1(dep.Dependencies, childKey, edges)
		}
	}
}

func findRoots(packages map[string]packageLockPkg) []string {
	var roots []string
	for path, pkg := range packages {
		if path == "" || (!strings.Contains(path, "node_modules/") && pkg.Name != "") {
			roots = append(roots, path)
		}
	}
	return roots
}

func extractName(pkgPath string, pkg packageLockPkg) string {
	if idx := strings.LastIndex(pkgPath, "node_modules/"); idx != -1 {
		return canonicalName(pkgPath[idx+len("node_modules/"):], pkg)
	}
	return pkg.Name
}

// canonicalName resolves an npm alias to its real package name. An aliased
// dependency ("react-is-18": "npm:react-is@18.3.1") installs under the alias
// label but npm records the real name in the entry's "name" field. The
// registry and source-repo checks must key off the real name, not the label,
// or they query a non-existent package and 404. Non-aliased entries omit "name"
// (or set it equal to the label), so they fall through unchanged — a genuinely
// absent / typosquatted name keeps its identity and still flags as not-found.
func canonicalName(label string, pkg packageLockPkg) string {
	if pkg.Name != "" && pkg.Name != label {
		return pkg.Name
	}
	return label
}

func isDirectDep(pkgPath string, roots []string, packages map[string]packageLockPkg) bool {
	// Workspace packages (no node_modules/ in path, has name) are direct deps
	if !strings.Contains(pkgPath, "node_modules/") {
		return packages[pkgPath].Name != ""
	}

	// Find which root this package belongs to
	var root string
	for _, r := range roots {
		if r == "" {
			continue
		}
		if strings.HasPrefix(pkgPath, r+"/") && len(r) > len(root) {
			root = r
		}
	}

	// Build expected direct path pattern
	var directPrefix string
	if root == "" {
		directPrefix = "node_modules/"
	} else {
		directPrefix = root + "/node_modules/"
	}

	if !strings.HasPrefix(pkgPath, directPrefix) {
		return false
	}

	// Check it's at the first node_modules level (no nested node_modules)
	remainder := pkgPath[len(directPrefix):]
	if strings.Contains(remainder, "node_modules/") {
		return false
	}

	// Check if declared in root's dependencies
	rootPkg := packages[root]
	pkgName := remainder // remainder is the package name at this point
	return rootPkg.Dependencies[pkgName] != "" ||
		rootPkg.DevDependencies[pkgName] != "" ||
		rootPkg.OptionalDependencies[pkgName] != ""
}

func resolvePackage(path string, packages map[string]packageLockPkg, depth int) (packageLockPkg, bool) {
	if depth > 10 {
		return packageLockPkg{}, false
	}
	pkg, ok := packages[path]
	if !ok {
		return packageLockPkg{}, false
	}
	if pkg.Link && pkg.Resolved != "" {
		return resolvePackage(pkg.Resolved, packages, depth+1)
	}
	return pkg, true
}

func resolvePackageByName(fromPath, depName string, packages map[string]packageLockPkg) (packageLockPkg, bool) {
	current := fromPath

	for {
		candidate := current + "/node_modules/" + depName
		if current == "" {
			candidate = "node_modules/" + depName
		}

		if pkg, ok := resolvePackage(candidate, packages, 0); ok {
			return pkg, true
		}

		if current == "" {
			break
		}

		if idx := strings.LastIndex(current, "/"); idx >= 0 {
			current = current[:idx]
		} else {
			current = ""
		}
	}

	return packageLockPkg{}, false
}

func makeKey(name, version string) string {
	if version == "" {
		return "package/npm/" + name
	}
	return "package/npm/" + name + "?version=" + version
}

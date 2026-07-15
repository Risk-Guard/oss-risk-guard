package bun

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/tidwall/jsonc"

	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/def"
	"github.com/Risk-Guard/oss-risk-guard/src/ecosystem/lockfile"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

var LockfileNames = []string{"bun.lock", "bun.lockb"}

var Manager = def.NewPackageManager("bun", "npm", LockfileNames...)

func DetectLockfile(manifestDir, repoRoot string) *string {
	return lockfile.Detect(manifestDir, repoRoot, LockfileNames...)
}

func OwnsLockfile(filename string) bool {
	return slices.Contains(LockfileNames, filename)
}

type bunLockFile struct {
	LockfileVersion int                        `json:"lockfileVersion"`
	Workspaces      map[string]bunWorkspace    `json:"workspaces"`
	Packages        map[string]json.RawMessage `json:"packages"`
}

type bunWorkspace struct {
	Name                 string            `json:"name"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// bunPackageMeta is index 2 of a bun.lock packages array. Only dependencies and
// optionalDependencies produce installed transitive edges; peerDependencies and
// a package's own devDependencies are deliberately not decoded.
type bunPackageMeta struct {
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

type bunPackage struct {
	Name    string
	Version string
	Meta    bunPackageMeta
}

func ParseLockfile(content []byte) ([]models.DepsTreeEdge, error) {
	if len(content) == 0 {
		return nil, fmt.Errorf("bun.lock file is empty")
	}

	// Binary guard: ParseLockfile only receives content (not the filename), so
	// this is how we distinguish binary bun.lockb from a text bun.lock. If the
	// first non-whitespace byte is not '{', treat it as binary bun.lockb and
	// skip silently (nil, nil) — matching today's stub behavior. Returning an
	// error here would raise a spurious CRITICAL SOURCE_MALFORMED_METADATA
	// finding on bun.lockb-only repos (Bun <1.2), a regression. A corrupt text
	// bun.lock still starts with '{', falls through, and errors below as it
	// should.
	if !startsWithBrace(content) {
		return nil, nil
	}

	// jsonc.ToJSON strips comments and trailing commas (Bun writes both),
	// replacing them with whitespace so offsets and string contents are
	// preserved for the standard json decoder.
	normalized := jsonc.ToJSON(content)

	var lf bunLockFile
	if err := json.Unmarshal(normalized, &lf); err != nil {
		return nil, fmt.Errorf("parsing bun.lock: %w", err)
	}

	if len(lf.Workspaces) == 0 && len(lf.Packages) == 0 {
		return nil, fmt.Errorf("unsupported bun.lock: no workspaces and no packages")
	}

	index := make(map[string]bunPackage, len(lf.Packages))
	for key, raw := range lf.Packages {
		if pkg, ok := parseBunPackage(raw); ok {
			index[key] = pkg
		}
	}

	seen := make(map[string]struct{})
	var edges []models.DepsTreeEdge

	addEdge := func(parent, child string, dev bool) {
		if child == "" {
			return
		}
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

	// Direct deps: every workspace entry (root "" and members) contributes.
	// Resolve names from top-level; skip names absent from packages (local /
	// workspace self-references).
	for _, ws := range lf.Workspaces {
		emitDirect := func(deps map[string]string, dev bool) {
			for name := range deps {
				if target, ok := resolveKey("", name, index); ok {
					addEdge("", makeKey(target.Name, target.Version), dev)
				}
			}
		}
		emitDirect(ws.Dependencies, false)
		emitDirect(ws.OptionalDependencies, false)
		emitDirect(ws.DevDependencies, true)
	}

	// Transitive deps: for each package entry, resolve each of its
	// dependencies + optionalDependencies via walk-up from its own key.
	for parentKey, pkg := range index {
		parentChildKey := makeKey(pkg.Name, pkg.Version)
		emitTransitive := func(deps map[string]string) {
			for depName := range deps {
				if target, ok := resolveKey(parentKey, depName, index); ok {
					addEdge(parentChildKey, makeKey(target.Name, target.Version), false)
				}
			}
		}
		emitTransitive(pkg.Meta.Dependencies)
		emitTransitive(pkg.Meta.OptionalDependencies)
	}

	lockfile.PropagateDevFlag(edges, "")
	return edges, nil
}

func startsWithBrace(content []byte) bool {
	for _, b := range content {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '{':
			return true
		default:
			return false
		}
	}
	return false
}

// parseBunPackage destructures a bun.lock packages value:
// [descriptor, registry, metadata, integrity] (length 2–4; metadata/integrity
// optional). Returns false for entries that are empty or whose descriptor is
// unusable so a single bad entry doesn't fail the whole file.
func parseBunPackage(raw json.RawMessage) (bunPackage, bool) {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) < 1 {
		return bunPackage{}, false
	}

	var descriptor string
	if err := json.Unmarshal(arr[0], &descriptor); err != nil {
		return bunPackage{}, false
	}

	name, version, ok := splitDescriptor(descriptor)
	if !ok {
		return bunPackage{}, false
	}

	var meta bunPackageMeta
	if len(arr) >= 3 {
		// Best-effort: absent/odd metadata just yields no transitive edges.
		_ = json.Unmarshal(arr[2], &meta)
	}

	return bunPackage{Name: name, Version: version, Meta: meta}, true
}

// splitDescriptor splits "name@version" on the last '@' so scoped names survive
// (@babel/core@7.24.0 -> @babel/core + 7.24.0). A leading-'@' only descriptor
// (scoped name, no version) keeps its name and an empty version. An unscoped
// name with no '@' at all (e.g. "noatsign") is not a usable descriptor and is
// rejected so malformed entries skip consistently.
func splitDescriptor(d string) (name, version string, ok bool) {
	if d == "" {
		return "", "", false
	}
	idx := strings.LastIndex(d, "@")
	if idx < 0 {
		return "", "", false
	}
	if idx == 0 {
		return d, "", true
	}
	return d[:idx], d[idx+1:], true
}

// resolveKey resolves dependency dep declared by the entry at fromKey using
// bun's nesting-path walk-up: try fromKey/dep, then strip fromKey's last
// path segment and retry, finally top-level dep.
//
// The segment stripping is not scope-aware (stripping "@babel/core" yields a
// bogus intermediate "@babel"), but this is harmless: real scoped keys are
// atomic, so bogus intermediates never collide with a real packages key and the
// walk always falls through to the correct top-level entry.
func resolveKey(fromKey, dep string, index map[string]bunPackage) (bunPackage, bool) {
	current := fromKey
	for {
		candidate := dep
		if current != "" {
			candidate = current + "/" + dep
		}
		if pkg, ok := index[candidate]; ok {
			return pkg, true
		}
		if current == "" {
			break
		}
		if i := strings.LastIndex(current, "/"); i >= 0 {
			current = current[:i]
		} else {
			current = ""
		}
	}
	return bunPackage{}, false
}

func makeKey(name, version string) string {
	if version == "" {
		return "package/npm/" + name
	}
	return "package/npm/" + name + "?version=" + version
}

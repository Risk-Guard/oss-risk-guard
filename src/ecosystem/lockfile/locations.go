package lockfile

import (
	"strings"

	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

// AttachManifestLocations stamps each lockfile edge's Location with the
// manifest-side LocationInfo (file + line in the manifest) for its dep.
// Direct edges (ParentKey == "") are matched by package name; transitive
// edges inherit the Location of the direct ancestor that pulled them in,
// resolved by walking the edge DAG to a fixed point.
//
// Names are extracted from the AnalysisIdentifier ("package/<eco>/<name>")
// and the lockfile ChildKey ("package/<eco>/<name>?version=<v>"). Matching
// uses whatever normalization each ecosystem already applies (e.g. PEP 503
// for pypi); both sides come from the same ecosystem and are pre-normalized
// by their respective parsers, so no extra normalization happens here.
func AttachManifestLocations(edges []models.DepsTreeEdge, deps []models.Dependency) []models.DepsTreeEdge {
	if len(edges) == 0 || len(deps) == 0 {
		return edges
	}

	locByName := make(map[string]*models.LocationInfo, len(deps))
	for _, d := range deps {
		if d.Location == nil {
			continue
		}
		locByName[nameFromKey(d.AnalysisIdentifier)] = d.Location
	}
	if len(locByName) == 0 {
		return edges
	}

	locByKey := make(map[string]*models.LocationInfo, len(edges))
	for i := range edges {
		e := &edges[i]
		if e.ParentKey != "" {
			continue
		}
		if loc, ok := locByName[nameFromKey(e.ChildKey)]; ok {
			e.Location = loc
			locByKey[e.ChildKey] = loc
		}
	}

	for {
		changed := false
		for i := range edges {
			e := &edges[i]
			if e.Location != nil || e.ParentKey == "" {
				continue
			}
			loc, ok := locByKey[e.ParentKey]
			if !ok {
				continue
			}
			e.Location = loc
			if _, set := locByKey[e.ChildKey]; !set {
				locByKey[e.ChildKey] = loc
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return edges
}

// nameFromKey extracts the package name from either an AnalysisIdentifier
// ("package/<eco>/<name>") or a ChildKey ("package/<eco>/<name>?version=...").
func nameFromKey(key string) string {
	rest := strings.TrimPrefix(key, "package/")
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[i+1:]
	}
	name, _, _ := strings.Cut(rest, "?")
	return name
}

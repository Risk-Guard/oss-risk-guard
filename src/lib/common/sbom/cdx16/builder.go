package cdx16

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/depsgraph"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom/sbomkey"

	"github.com/google/uuid"
)

type Builder struct {
	rootKey  string
	nodes    map[string]depsgraph.SBOMNode
	toolName string
}

func NewBuilder(rootKey string, nodes []depsgraph.SBOMNode, toolName string) *Builder {
	nodeMap := make(map[string]depsgraph.SBOMNode, len(nodes))
	for _, n := range nodes {
		nodeMap[n.Key] = n
	}
	return &Builder{
		rootKey:  rootKey,
		nodes:    nodeMap,
		toolName: toolName,
	}
}

func (b *Builder) Build() (*BOM, error) {
	serial := "urn:uuid:" + uuid.New().String()

	refByKey := b.buildRefs()

	var rootComponent *Component
	if node, ok := b.nodes[b.rootKey]; ok {
		rc := buildComponent(node, refByKey[node.Key])
		rootComponent = &rc
	}

	components := make([]Component, 0, len(b.nodes))
	deps := make([]Dep, 0, len(b.nodes))

	for _, node := range b.nodes {
		comp := buildComponent(node, refByKey[node.Key])
		components = append(components, comp)

		dep := Dep{Ref: refByKey[node.Key]}
		for _, childKey := range node.Deps {
			if _, exists := b.nodes[childKey]; exists {
				dep.DependsOn = append(dep.DependsOn, refByKey[childKey])
			}
		}
		deps = append(deps, dep)
	}

	bom := &BOM{
		BOMFormat:    BOMFormat,
		SpecVersion:  SpecVersion,
		SerialNumber: serial,
		Version:      1,
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: &ToolsContainer{
				Components: []Component{
					{
						Type:   "application",
						BOMRef: fmt.Sprintf("tool-%s", bomRef(b.toolName)),
						Name:   b.toolName,
					},
				},
			},
			Component: rootComponent,
		},
		Components:   components,
		Dependencies: deps,
	}

	return bom, nil
}

// buildRefs assigns every node its bom-ref, preferring the node's purl so the
// identifier means something to tools other than this one. Anything without a
// purl that round-trips — a source-tree root, an unresolved ecosystem, or a
// purl another node already claimed — keeps the base64url-encoded analysis key.
// Keys are walked in sorted order so a contested purl goes to the same node
// every time.
func (b *Builder) buildRefs() map[string]string {
	keys := make([]string, 0, len(b.nodes))
	for key := range b.nodes {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	refs := make(map[string]string, len(b.nodes))
	taken := make(map[string]bool, len(b.nodes))
	for _, key := range keys {
		ref := bomRef(key)
		if p := sbomkey.StableNodePURL(b.nodes[key], key); p != "" && !taken[p] {
			ref = p
		}
		refs[key] = ref
		taken[ref] = true
	}
	return refs
}

func buildComponent(node depsgraph.SBOMNode, ref string) Component {
	name := node.Key
	if node.PackageName != nil {
		name = *node.PackageName
	}

	version := ""
	if node.PackageVersion != nil {
		version = *node.PackageVersion
	}

	comp := Component{
		Type:    "library",
		BOMRef:  ref,
		Name:    name,
		Version: version,
		PURL:    sbomkey.NodePURL(node),
	}

	if len(node.Violations) > 0 {
		var props []Property
		for _, v := range node.Violations {
			props = append(props, Property{
				Name:  "riskguard:violation:" + v.CheckCode,
				Value: v.Rationale,
			})
			if len(v.Evidence) > 0 {
				evidenceJSON, _ := json.Marshal(v.Evidence)
				props = append(props, Property{
					Name:  "riskguard:evidence:" + v.CheckCode,
					Value: string(evidenceJSON),
				})
			}
		}
		comp.Properties = props
	}

	if node.Location != nil && node.Location.File != nil {
		occ := Occurrence{Location: *node.Location.File}
		if node.Location.LineNumber != nil {
			occ.Line = *node.Location.LineNumber
		}
		comp.Evidence = &Evidence{Occurrences: []Occurrence{occ}}
	}

	return comp
}

func bomRef(key string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(key))
}

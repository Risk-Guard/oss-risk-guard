package cdx16

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Risk-Guard/oss-risk-guard/src/depsgraph"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom/purl"
	"time"

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

	var rootComponent *Component
	if node, ok := b.nodes[b.rootKey]; ok {
		rc := buildComponent(node)
		rootComponent = &rc
	}

	components := make([]Component, 0, len(b.nodes))
	deps := make([]Dep, 0, len(b.nodes))

	for _, node := range b.nodes {
		comp := buildComponent(node)
		components = append(components, comp)

		dep := Dep{Ref: bomRef(node.Key)}
		for _, childKey := range node.Deps {
			if _, exists := b.nodes[childKey]; exists {
				dep.DependsOn = append(dep.DependsOn, bomRef(childKey))
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

func buildComponent(node depsgraph.SBOMNode) Component {
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
		BOMRef:  bomRef(node.Key),
		Name:    name,
		Version: version,
	}

	if node.Ecosystem != nil && node.PackageName != nil {
		comp.PURL = purl.Build(*node.Ecosystem, *node.PackageName, version)
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

	return comp
}

func bomRef(key string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(key))
}

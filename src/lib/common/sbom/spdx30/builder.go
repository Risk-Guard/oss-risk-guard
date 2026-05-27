package spdx30

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/Risk-Guard/oss-risk-guard/src/depsgraph"
	"github.com/Risk-Guard/oss-risk-guard/src/lib/common/sbom/purl"
)

type Builder struct {
	rootKey   string
	nodes     map[string]depsgraph.SBOMNode
	toolName  string
	namespace string
}

func NewBuilder(rootKey string, nodes []depsgraph.SBOMNode, toolName string) *Builder {
	nodeMap := make(map[string]depsgraph.SBOMNode, len(nodes))
	for _, n := range nodes {
		nodeMap[n.Key] = n
	}
	return &Builder{
		rootKey:   rootKey,
		nodes:     nodeMap,
		toolName:  toolName,
		namespace: "app.ossriskguard/" + b64(rootKey) + "." + time.Now().UTC().Format(time.RFC3339),
	}
}

func (b *Builder) Build() (*Document, error) {
	creationInfoID := "_:creationinfo"
	orgID := b.namespace + "#org-risk-guard"
	toolID := b.namespace + "#tool-" + b64(b.toolName)
	docID := b.namespace + "#SPDXRef-DOCUMENT"

	creationInfo := CreationInfo{
		ID:           creationInfoID,
		Type:         "CreationInfo",
		SpecVersion:  SpecVer,
		Created:      time.Now().UTC().Format(time.RFC3339),
		CreatedBy:    []string{orgID},
		CreatedUsing: []string{toolID},
	}

	org := Organization{
		Type:         "Organization",
		SpdxID:       orgID,
		Name:         "Risk Guard",
		CreationInfo: creationInfoID,
	}

	tool := Tool{
		Type:         "Tool",
		SpdxID:       toolID,
		Name:         b.toolName,
		CreationInfo: creationInfoID,
	}

	var packages []Package
	var relationships []Relationship
	var elementIDs []string
	relIndex := 0

	files := make(map[string]File)
	var snippets []Snippet

	// Sort keys for deterministic output ordering of packages, files, and
	// hasDependencyManifest relationships.
	keys := make([]string, 0, len(b.nodes))
	for k := range b.nodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		node := b.nodes[key]
		pkg := b.buildPackage(key, node, creationInfoID)
		packages = append(packages, pkg)
		elementIDs = append(elementIDs, pkg.SpdxID)

		for _, childKey := range node.Deps {
			if _, exists := b.nodes[childKey]; exists {
				relID := fmt.Sprintf("%s#Relationship-%d", b.namespace, relIndex)
				relIndex++
				rel := Relationship{
					Type:             "Relationship",
					SpdxID:           relID,
					CreationInfo:     creationInfoID,
					RelationshipType: RelationshipDependsOn,
					From:             b.namespace + "#" + b64(key),
					To:               []string{b.namespace + "#" + b64(childKey)},
				}
				relationships = append(relationships, rel)
				elementIDs = append(elementIDs, relID)
			}
		}

		if node.Location != nil && node.Location.File != nil {
			filePath := *node.Location.File
			fileID := b.namespace + "#file-" + b64(filePath)
			if _, ok := files[filePath]; !ok {
				files[filePath] = File{
					Type:         "software_File",
					SpdxID:       fileID,
					Name:         filePath,
					CreationInfo: creationInfoID,
				}
			}

			// Target the File directly when no line is known; otherwise emit a
			// Snippet element carrying the line range and target that.
			manifestTarget := fileID
			if node.Location.LineNumber != nil {
				ln := *node.Location.LineNumber
				snipID := b.namespace + "#snippet-" + b64(key+"@"+filePath)
				snippets = append(snippets, Snippet{
					Type:            "software_Snippet",
					SpdxID:          snipID,
					Name:            fmt.Sprintf("%s#L%d", filePath, ln),
					CreationInfo:    creationInfoID,
					SnippetFromFile: fileID,
					LineRange: &PositiveIntegerRange{
						Type:              "PositiveIntegerRange",
						BeginIntegerRange: ln,
						EndIntegerRange:   ln,
					},
				})
				elementIDs = append(elementIDs, snipID)
				manifestTarget = snipID
			}

			relID := fmt.Sprintf("%s#Relationship-%d", b.namespace, relIndex)
			relIndex++
			rel := Relationship{
				Type:             "Relationship",
				SpdxID:           relID,
				CreationInfo:     creationInfoID,
				RelationshipType: RelationshipHasDependencyManifest,
				From:             b.namespace + "#" + b64(key),
				To:               []string{manifestTarget},
			}
			relationships = append(relationships, rel)
			elementIDs = append(elementIDs, relID)
		}
	}

	filePaths := make([]string, 0, len(files))
	for p := range files {
		filePaths = append(filePaths, p)
	}
	sort.Strings(filePaths)
	fileElements := make([]File, 0, len(files))
	for _, p := range filePaths {
		fileElements = append(fileElements, files[p])
		elementIDs = append(elementIDs, files[p].SpdxID)
	}

	var rootElements []string
	if _, exists := b.nodes[b.rootKey]; exists {
		rootPkgID := b.namespace + "#" + b64(b.rootKey)
		rootElements = []string{rootPkgID}

		relID := fmt.Sprintf("%s#Relationship-%d", b.namespace, relIndex)
		descRel := Relationship{
			Type:             "Relationship",
			SpdxID:           relID,
			CreationInfo:     creationInfoID,
			RelationshipType: RelationshipDescribes,
			From:             docID,
			To:               []string{rootPkgID},
		}
		relationships = append(relationships, descRel)
		elementIDs = append(elementIDs, relID)
	}

	spdxDoc := SpdxDocument{
		Type:               "SpdxDocument",
		SpdxID:             docID,
		Name:               "SBOM for " + b.rootKey,
		Element:            elementIDs,
		RootElement:        rootElements,
		CreationInfo:       creationInfoID,
		ProfileConformance: []string{ProfileSoftware},
	}

	graph := make([]any, 0, 4+len(packages)+len(relationships)+len(fileElements)+len(snippets))
	graph = append(graph, creationInfo, org, tool, spdxDoc)
	for i := range packages {
		graph = append(graph, packages[i])
	}
	for i := range fileElements {
		graph = append(graph, fileElements[i])
	}
	for i := range snippets {
		graph = append(graph, snippets[i])
	}
	for i := range relationships {
		graph = append(graph, relationships[i])
	}

	return &Document{
		Context: Context,
		Graph:   graph,
	}, nil
}

func (b *Builder) buildPackage(key string, node depsgraph.SBOMNode, creationInfoID string) Package {
	name := key
	if node.PackageName != nil {
		name = *node.PackageName
	}

	version := ""
	if node.PackageVersion != nil {
		version = *node.PackageVersion
	}

	pkg := Package{
		Type:             "software_Package",
		SpdxID:           b.namespace + "#" + b64(key),
		Name:             name,
		CreationInfo:     creationInfoID,
		PackageVersion:   version,
		DownloadLocation: NoAssertion,
		CopyrightText:    NoAssertion,
	}

	if node.Ecosystem != nil && node.PackageName != nil {
		pkg.PackageURL = purl.Build(*node.Ecosystem, *node.PackageName, version)
	}

	if len(node.Violations) > 0 {
		var entries []CdxPropertyEntry
		for _, v := range node.Violations {
			entries = append(entries, CdxPropertyEntry{
				Type:  "extension_CdxPropertyEntry",
				Name:  "riskguard:violation:" + v.CheckCode,
				Value: v.Rationale,
			})
			if len(v.Evidence) > 0 {
				evidenceJSON, _ := json.Marshal(v.Evidence)
				entries = append(entries, CdxPropertyEntry{
					Type:  "extension_CdxPropertyEntry",
					Name:  "riskguard:evidence:" + v.CheckCode,
					Value: string(evidenceJSON),
				})
			}
		}
		pkg.Extensions = []CdxPropertiesExtension{{
			Type:       "extension_CdxPropertiesExtension",
			Properties: entries,
		}}
	}

	return pkg
}

func b64(key string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(key))
}

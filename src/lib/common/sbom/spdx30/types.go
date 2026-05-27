package spdx30

const (
	Context     = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
	SpecVer     = "3.0.1"
	NoAssertion = "NOASSERTION"

	RelationshipDescribes             = "describes"
	RelationshipDependsOn             = "dependsOn"
	RelationshipHasDependencyManifest = "hasDependencyManifest"

	ProfileSoftware = "software"
)

type Document struct {
	Context string `json:"@context"`
	Graph   []any  `json:"@graph"`
}

// CreationInfo is a shared blank node referenced by all elements.
type CreationInfo struct {
	ID           string   `json:"@id"`
	Type         string   `json:"type"`
	SpecVersion  string   `json:"specVersion"`
	Created      string   `json:"created"`
	CreatedBy    []string `json:"createdBy"`
	CreatedUsing []string `json:"createdUsing"`
}

type Organization struct {
	Type         string `json:"type"`
	SpdxID       string `json:"spdxId"`
	Name         string `json:"name"`
	CreationInfo string `json:"creationInfo"`
}

type Tool struct {
	Type         string `json:"type"`
	SpdxID       string `json:"spdxId"`
	Name         string `json:"name"`
	CreationInfo string `json:"creationInfo"`
}

type SpdxDocument struct {
	Type               string   `json:"type"`
	SpdxID             string   `json:"spdxId"`
	Name               string   `json:"name"`
	Element            []string `json:"element"`
	RootElement        []string `json:"rootElement"`
	CreationInfo       string   `json:"creationInfo"`
	ProfileConformance []string `json:"profileConformance"`
}

type CdxPropertiesExtension struct {
	Type       string             `json:"type"`
	Properties []CdxPropertyEntry `json:"extension_cdxProperty"`
}

type CdxPropertyEntry struct {
	Type  string `json:"type"`
	Name  string `json:"extension_cdxPropName"`
	Value string `json:"extension_cdxPropValue,omitempty"`
}

type Package struct {
	Type             string                   `json:"type"`
	SpdxID           string                   `json:"spdxId"`
	Name             string                   `json:"name"`
	CreationInfo     string                   `json:"creationInfo"`
	PackageVersion   string                   `json:"software_packageVersion,omitempty"`
	PackageURL       string                   `json:"software_packageUrl,omitempty"`
	DownloadLocation string                   `json:"software_downloadLocation"`
	CopyrightText    string                   `json:"software_copyrightText"`
	Extensions       []CdxPropertiesExtension `json:"extension,omitempty"`
}

type Relationship struct {
	Type             string   `json:"type"`
	SpdxID           string   `json:"spdxId"`
	CreationInfo     string   `json:"creationInfo"`
	RelationshipType string   `json:"relationshipType"`
	From             string   `json:"from"`
	To               []string `json:"to"`
}

type File struct {
	Type         string `json:"type"`
	SpdxID       string `json:"spdxId"`
	Name         string `json:"name"`
	CreationInfo string `json:"creationInfo"`
}

type Snippet struct {
	Type            string                `json:"type"`
	SpdxID          string                `json:"spdxId"`
	Name            string                `json:"name,omitempty"`
	CreationInfo    string                `json:"creationInfo"`
	SnippetFromFile string                `json:"software_snippetFromFile"`
	LineRange       *PositiveIntegerRange `json:"software_lineRange,omitempty"`
}

type PositiveIntegerRange struct {
	Type              string `json:"type"`
	BeginIntegerRange int    `json:"beginIntegerRange"`
	EndIntegerRange   int    `json:"endIntegerRange"`
}

package cdx16

const (
	BOMFormat   = "CycloneDX"
	SpecVersion = "1.6"
)

type BOM struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     Metadata    `json:"metadata"`
	Components   []Component `json:"components"`
	Dependencies []Dep       `json:"dependencies"`
}

type Metadata struct {
	Timestamp string          `json:"timestamp"`
	Tools     *ToolsContainer `json:"tools,omitempty"`
	Component *Component      `json:"component,omitempty"`
}

type ToolsContainer struct {
	Components []Component `json:"components"`
}

type Component struct {
	Type       string     `json:"type"`
	BOMRef     string     `json:"bom-ref"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	PURL       string     `json:"purl,omitempty"`
	Properties []Property `json:"properties,omitempty"`
	Evidence   *Evidence  `json:"evidence,omitempty"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Evidence struct {
	Occurrences []Occurrence `json:"occurrences,omitempty"`
}

type Occurrence struct {
	Location string `json:"location"`
	Line     int    `json:"line,omitempty"`
}

type Dep struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

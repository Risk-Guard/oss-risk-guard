package executiondag

type SourceCategory string

const (
	SourceCategoryVulnerability SourceCategory = "vulnerability"
	SourceCategoryRegistry      SourceCategory = "registry"
	SourceCategoryReference     SourceCategory = "reference"
)

type Source struct {
	Name        string         `json:"name" jsonschema:"description=Human-readable name of the data source"`
	Description string         `json:"description" jsonschema:"description=Description of what data this source provides"`
	URL         string         `json:"url" jsonschema:"description=Base URL of the data source API or website"`
	Category    SourceCategory `json:"category,omitempty" jsonschema:"description=Classification of the data source type,enum=vulnerability,enum=registry,enum=reference"`
	Version     string         `json:"version,omitempty" jsonschema:"description=Version of the data source (e.g. CWE database version)"`
}

func (s Source) ToDataSourceInfo() DataSourceInfo {
	return DataSourceInfo{Name: s.Name, Description: s.Description, URL: s.URL}
}

type SourceProvider interface {
	GetSources() map[string]Source
}

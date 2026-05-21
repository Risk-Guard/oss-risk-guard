package def

import (
	"fmt"

	executiondag "github.com/Risk-Guard/oss-risk-guard/src/execution-dag"
)

type NameEncoder func(name string) string

type NameNormalizer func(name string) string

type Definition struct {
	Name        string
	DisplayName string
	Source      executiondag.Source

	OSVEcosystem  string
	GHSAEcosystem string

	PURLType string

	PackageAPIURLFormat  string
	PackagePageURLFormat string

	DependencyFilePatterns []string
	SkipDirectories        []string

	EncodePURLName NameEncoder
	NormalizeName  NameNormalizer
}

func (d *Definition) BuildPackageAPIURL(packageName string) string {
	return fmt.Sprintf(d.PackageAPIURLFormat, d.Source.URL, packageName)
}

func (d *Definition) BuildPackagePageURL(packageName string) string {
	return fmt.Sprintf(d.PackagePageURLFormat, packageName)
}

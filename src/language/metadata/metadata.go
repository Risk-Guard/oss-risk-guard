package metadata

import (
	"fmt"

	executiondag "risk-guard/src/execution-dag"
)

type Metadata struct {
	Ecosystem            string
	DisplayName          string
	Source               executiondag.Source
	OSVEcosystem         string
	GHSAEcosystem        string
	PackageURLFormat     string
	PackagePageURLFormat string
}

func (m *Metadata) BuildPackageURL(packageName string) string {
	return fmt.Sprintf(m.PackageURLFormat, m.Source.URL, packageName)
}

// BuildPackagePageURL constructs the user-facing package page URL.
func (m *Metadata) BuildPackagePageURL(packageName string) string {
	return fmt.Sprintf(m.PackagePageURLFormat, packageName)
}

package dependency_parser

import (
	"risk-guard/src/models"
)

type DependencyParser interface {
	Parse(repoPath string) (*models.DependencyMetadata, error)
	Ecosystem() string
}

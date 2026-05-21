package dependency_parser

import (
	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

type DependencyParser interface {
	Parse(repoPath string) (*models.DependencyMetadata, error)
	Ecosystem() string
}

package fetcher

import (
	"context"

	"github.com/Risk-Guard/oss-risk-guard/src/artifact"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

type Fetcher interface {
	Fetch(ctx context.Context, pkg models.PackageInfo, dist *models.DistributionInfo) (*artifact.ArtifactExtraction, error)
}

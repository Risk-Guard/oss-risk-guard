package fetcher

import (
	"context"

	"github.com/Risk-Guard/oss-risk-guard/src/api/routes"
	"github.com/Risk-Guard/oss-risk-guard/src/models"
)

type Fetcher interface {
	Fetch(ctx context.Context, pkg models.PackageInfo, dist *models.DistributionInfo) (*routes.ArtifactExtraction, error)
}

package fetcher

import (
	"context"
	"risk-guard/src/api/routes"
	"risk-guard/src/models"
)

type Fetcher interface {
	Fetch(ctx context.Context, pkg models.PackageInfo, dist *models.DistributionInfo) (*routes.ArtifactExtraction, error)
}

package localfetcher

import (
	"context"
	"fmt"
	"path/filepath"
	"risk-guard/src/api/routes"
	"risk-guard/src/artifact"
	"risk-guard/src/ctxutil"
	"risk-guard/src/models"

	"go.uber.org/zap"
)

type Fetcher struct{}

func New() *Fetcher {
	return &Fetcher{}
}

func (Fetcher) Fetch(ctx context.Context, pkg models.PackageInfo, dist *models.DistributionInfo) (*routes.ArtifactExtraction, error) {
	log := ctxutil.GetLogger(ctx)

	filename := dist.Filename
	if filename == "" {
		filename = filepath.Base(dist.URL)
	}

	log.Debug("streaming artifact",
		zap.String("ecosystem", pkg.Ecosystem),
		zap.String("package", pkg.Name),
		zap.String("url", dist.URL))

	extraction, err := artifact.StreamExtractAndVerify(ctx, dist, filename, pkg.Ecosystem)
	if err != nil {
		return nil, fmt.Errorf("extracting artifact: %w", err)
	}

	log.Debug("artifact extracted",
		zap.String("ecosystem", pkg.Ecosystem),
		zap.String("package", pkg.Name),
		zap.Int("files", len(extraction.Files)),
		zap.Bool("verified", extraction.Verified))

	return &routes.ArtifactExtraction{
		Ecosystem:       pkg.Ecosystem,
		PackageName:     pkg.Name,
		TarballFilename: filename,
		Files:           extraction.Files,
		ArtifactURL:     dist.URL,
		Verified:        extraction.Verified,
		VerifyError:     extraction.VerifyError,
	}, nil
}

package artifact

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	riskhttp "github.com/Risk-Guard/oss-risk-guard/src/http"
)

const DownloadTimeout = 5 * time.Minute

type StreamResult struct {
	Body        io.ReadCloser
	ContentType string
}

func StreamDownload(ctx context.Context, url string) (*StreamResult, error) {
	client := riskhttp.NewHTTPClientWithTimeout(DownloadTimeout)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := client.Do(req) //nolint:gosec // URL from controlled internal callers
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return &StreamResult{
		Body:        resp.Body,
		ContentType: resp.Header.Get("Content-Type"),
	}, nil
}

package pypi

import "time"

// PyPIFetchMetadata stores HTTP request/response metadata for PyPI API calls
type PyPIFetchMetadata struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers,omitempty"`
	FetchedAt  time.Time         `json:"fetched_at"`
	URL        string            `json:"url"`
}

package npm

import "time"

// NPMFetchMetadata stores HTTP request/response metadata for npm API calls
type NPMFetchMetadata struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers,omitempty"`
	FetchedAt  time.Time         `json:"fetched_at"`
	URL        string            `json:"url"`
}

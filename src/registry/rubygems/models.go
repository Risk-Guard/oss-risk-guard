package rubygems

import "time"

type RubyGemsFetchMetadata struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers,omitempty"`
	FetchedAt  time.Time         `json:"fetched_at"`
	URL        string            `json:"url"`
}

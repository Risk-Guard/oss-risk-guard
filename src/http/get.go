package http

import (
	"context"
	"encoding/json"
)

// GetJSONBytes performs a GET and returns the raw JSON response body together with the HTTP status
// code. On a non-2xx status it returns that status alongside a non-nil error so callers can branch on
// the code (for example 404 vs 401) while still surfacing transport failures (status 0).
func GetJSONBytes(ctx context.Context, url string, opts ...RequestOption) ([]byte, int, error) {
	raw, status, err := getJSONOnce[json.RawMessage](ctx, url, opts...)
	if err != nil {
		return nil, status, err
	}
	return []byte(*raw), status, nil
}

package http

import (
	"context"
	"encoding/json"
)

// PostJSONBytes POSTs a raw JSON body (e.g. an SBOM document) verbatim and returns the raw JSON response
// body together with the HTTP status code. On a non-2xx status it returns that status alongside a
// non-nil error so callers can branch on the code (for example 401 vs 502).
func PostJSONBytes(ctx context.Context, url string, body []byte, opts ...RequestOption) ([]byte, int, error) {
	resp, status, err := postJSONOnce[json.RawMessage](ctx, url, json.RawMessage(body), opts...)
	if err != nil {
		return nil, status, err
	}
	return []byte(*resp), status, nil
}

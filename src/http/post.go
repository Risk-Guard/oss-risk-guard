package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

// PostMultipart POSTs a pre-built body with the given Content-Type (a multipart/form-data body from
// mime/multipart) and returns the raw response body together with the HTTP status code. On a non-2xx
// status it returns that status alongside a non-nil error so callers can branch on the code.
func PostMultipart(ctx context.Context, url, contentType string, body []byte, opts ...RequestOption) ([]byte, int, error) {
	config := &requestConfig{
		client:             DefaultHTTPClient(),
		expectedStatusCode: http.StatusOK,
		headers:            make(map[string]string),
	}
	for _, opt := range opts {
		opt(config)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	for key, value := range config.headers {
		req.Header.Set(key, value)
	}

	resp, err := config.client.Do(req) //nolint:gosec // URL from controlled internal callers
	if err != nil {
		return nil, 0, fmt.Errorf("failed to execute request: %w", err)
	}

	statusCode := resp.StatusCode
	respBody, err := ReadAndValidateResponse(resp, config.expectedStatusCode)
	if err != nil {
		return nil, statusCode, err
	}
	return respBody, statusCode, nil
}

package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

func getJSONOnce[T any](ctx context.Context, url string, opts ...RequestOption) (*T, int, error) {
	config := &requestConfig{
		client:             DefaultHTTPClient(),
		expectedStatusCode: http.StatusOK,
		headers:            make(map[string]string),
	}

	for _, opt := range opts {
		opt(config)
	}

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	for key, value := range config.headers {
		req.Header.Set(key, value)
	}

	// Execute request
	resp, err := config.client.Do(req) //nolint:gosec // URL from controlled internal callers
	if err != nil {
		return nil, 0, fmt.Errorf("failed to execute request: %w", err)
	}

	// Capture response metadata before validation
	statusCode := resp.StatusCode

	// Read and validate response (uses existing utility)
	body, err := ReadAndValidateResponse(resp, config.expectedStatusCode)
	if err != nil {
		return nil, statusCode, err
	}

	// Parse JSON
	var result T
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, statusCode, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	return &result, statusCode, nil
}

func postJSONOnce[T any](ctx context.Context, url string, body any, opts ...RequestOption) (*T, int, error) {
	config := &requestConfig{
		client:             DefaultHTTPClient(),
		expectedStatusCode: http.StatusOK,
		headers:            make(map[string]string),
	}

	for _, opt := range opts {
		opt(config)
	}

	// Marshal request body to JSON
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Set Content-Type header
	req.Header.Set("Content-Type", "application/json")

	// Add custom headers
	for key, value := range config.headers {
		req.Header.Set(key, value)
	}

	// Execute request
	resp, err := config.client.Do(req) //nolint:gosec // URL from controlled internal callers
	if err != nil {
		return nil, 0, fmt.Errorf("failed to execute request: %w", err)
	}

	// Capture response metadata before validation
	statusCode := resp.StatusCode

	// Read and validate response
	respBody, err := ReadAndValidateResponse(resp, config.expectedStatusCode)
	if err != nil {
		return nil, statusCode, err
	}

	// Parse JSON
	var result T
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, statusCode, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	return &result, statusCode, nil
}

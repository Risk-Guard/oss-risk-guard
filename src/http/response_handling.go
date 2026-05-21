package http

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

type StatusCodeError struct {
	StatusCode int
	Body       string
}

func (e *StatusCodeError) Error() string {
	return fmt.Sprintf("unexpected status code %d: %s", e.StatusCode, e.Body)
}

func GetStatusCodeFromError(err error) (int, bool) {
	var statusErr *StatusCodeError
	if errors.As(err, &statusErr) {
		return statusErr.StatusCode, true
	}
	return 0, false
}

func ReadResponseBody(resp *http.Response) ([]byte, error) {
	var err error
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("failed to close response body: %w", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, err
}

func CheckStatusCode(resp *http.Response, body []byte, expectedCode int) error {
	if resp.StatusCode == expectedCode {
		return nil
	}

	bodyPreview := string(body)
	if len(bodyPreview) > 200 {
		bodyPreview = bodyPreview[:200] + "..."
	}

	return &StatusCodeError{
		StatusCode: resp.StatusCode,
		Body:       bodyPreview,
	}
}

func ReadAndValidateResponse(resp *http.Response, expectedCode int) ([]byte, error) {
	body, err := ReadResponseBody(resp)
	if err != nil {
		return nil, err
	}

	if err := CheckStatusCode(resp, body, expectedCode); err != nil {
		return nil, err
	}

	return body, nil
}

func TruncateBodyPreview(body []byte, maxLen int) string {
	bodyStr := string(body)
	if len(bodyStr) > maxLen {
		return bodyStr[:maxLen] + "..."
	}
	return bodyStr
}

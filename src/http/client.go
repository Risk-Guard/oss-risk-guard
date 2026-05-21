package http

import (
	"net/http"
	"time"
)

func NewHTTPClientWithTimeout(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
	}
}

// 30-second timeout used across most API clients.
func DefaultHTTPClient() *http.Client {
	return NewHTTPClientWithTimeout(30 * time.Second)
}

package http

import (
	"net/http"
)

type RequestOption func(*requestConfig)

type requestConfig struct {
	client             *http.Client
	expectedStatusCode int
	headers            map[string]string
}

func WithHeader(key, value string) RequestOption {
	return func(c *requestConfig) {
		c.headers[key] = value
	}
}

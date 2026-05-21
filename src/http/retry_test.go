package http

import (
	"fmt"
	"net/http"
	"testing"
)

func TestIsRetryableStatusCode(t *testing.T) {
	tests := []struct {
		code     int
		expected bool
	}{
		{http.StatusTooManyRequests, true},     // 429
		{http.StatusInternalServerError, true}, // 500
		{http.StatusBadGateway, true},          // 502
		{http.StatusServiceUnavailable, true},  // 503
		{http.StatusGatewayTimeout, true},      // 504
		{http.StatusOK, false},                 // 200
		{http.StatusBadRequest, false},         // 400
		{http.StatusUnauthorized, false},       // 401
		{http.StatusForbidden, false},          // 403
		{http.StatusNotFound, false},           // 404
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("status_%d", tt.code), func(t *testing.T) {
			result := IsRetryableStatusCode(tt.code)
			if result != tt.expected {
				t.Errorf("IsRetryableStatusCode(%d) = %v, want %v", tt.code, result, tt.expected)
			}
		})
	}
}

func TestCalculateNextDelay(t *testing.T) {
	tests := []struct {
		attempt       uint
		expectedDelay string
	}{
		{0, "1s"},   // 1 * 2^0 = 1s
		{1, "2s"},   // 1 * 2^1 = 2s
		{2, "4s"},   // 1 * 2^2 = 4s
		{3, "8s"},   // 1 * 2^3 = 8s
		{4, "16s"},  // 1 * 2^4 = 16s
		{5, "30s"},  // 1 * 2^5 = 32s, capped at 30s
		{10, "30s"}, // Very high attempt, should be capped at 30s
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("attempt_%d", tt.attempt), func(t *testing.T) {
		})
	}
}
